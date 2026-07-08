import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from vulnshield_common.ai_orchestrator import sanitize_for_llm, triage_findings
from vulnshield_common.entity_reports import generate_codereview_executive_report
from vulnshield_common.llm import SecurityLLMConfigurationError, get_security_llm
from vulnshield_common.messaging import publish_event
from vulnshield_common.scan_engines import EngineUnavailableError, run_semgrep
from vulnshield_common.scan_sandbox import normalize_cwe_id
from vulnshield_common.static_sast import analyze_source

SUPPORTED_LANGUAGES = {
    "python", "javascript", "typescript", "java", "go", "csharp", "ruby", "php",
    "c", "cpp", "rust", "kotlin", "swift",
}

ALLOWED_CODE_ROOTS = (
    "/app/code",
    "/tmp/vulnshield",
    "/workspace",
    "/code",
)

SOURCE_EXTENSIONS = {
    "python": {".py"},
    "javascript": {".js", ".jsx", ".mjs"},
    "typescript": {".ts", ".tsx"},
    "java": {".java"},
    "go": {".go"},
    "csharp": {".cs"},
    "ruby": {".rb"},
    "php": {".php"},
    "c": {".c", ".h"},
    "cpp": {".cpp", ".cc", ".hpp", ".h"},
    "rust": {".rs"},
    "kotlin": {".kt", ".kts"},
    "swift": {".swift"},
}


def _resolve_source(data: dict) -> tuple[str, str]:
    """Return (source_code, file_path) from repository, path, or pasted code."""
    if data.get("source_code"):
        fp = data.get("file_path") or f"submitted.{data['language'][:2]}"
        return data["source_code"], fp

    file_path = data.get("file_path")
    if file_path:
        path = Path(file_path).resolve()
        allowed = any(str(path).startswith(root) for root in ALLOWED_CODE_ROOTS)
        if not allowed and not os.getenv("CODE_REVIEW_ALLOW_ANY_PATH"):
            raise HTTPException(
                400,
                f"File path must be under an allowed directory or paste code directly. "
                f"Allowed roots: {', '.join(ALLOWED_CODE_ROOTS)}",
            )
        if not path.is_file():
            raise HTTPException(404, f"File not found: {file_path}")
        if path.stat().st_size > 512_000:
            raise HTTPException(400, "File exceeds maximum size of 512KB")
        return path.read_text(encoding="utf-8", errors="replace"), str(path)

    if data.get("repository_url"):
        return "", data.get("repository_url", "repository")

    raise HTTPException(400, "Provide source_code, file_path, or repository_url")


def _clone_repository(repo_url: str, branch: str = "main") -> Path:
    git_bin = shutil.which("git") or ("/usr/bin/git" if Path("/usr/bin/git").is_file() else None)
    if not git_bin:
        raise HTTPException(503, "git is required for repository scans but is not installed")
    tmp = Path(tempfile.mkdtemp(prefix="vulnshield-clone-"))
    cmd = [git_bin, "clone", "--depth", "1", "--branch", branch, repo_url, str(tmp)]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
    if result.returncode != 0:
        shutil.rmtree(tmp, ignore_errors=True)
        raise HTTPException(400, f"Git clone failed: {result.stderr[:500]}")
    return tmp


async def _scan_directory(repo_path: Path, language: str) -> list[dict]:
    findings: list[dict] = []
    exts = SOURCE_EXTENSIONS.get(language, {".py", ".js", ".ts", ".java", ".go"})

    for path in repo_path.rglob("*"):
        if not path.is_file() or path.suffix not in exts:
            continue
        if path.stat().st_size > 512_000:
            continue
        try:
            code = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(repo_path))
        findings.extend(analyze_source(code, rel, language))

    try:
        findings.extend(await run_semgrep(str(repo_path)))
    except EngineUnavailableError:
        pass

    deduped: list[dict] = []
    seen: set[str] = set()
    for f in findings:
        if f.get("severity") == "info" and len(deduped) > 0:
            continue
        key = f"{f.get('file_path')}:{f.get('line_start')}:{f.get('title')}"
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)
    return deduped


async def create_review(db: AsyncSession, data: dict, user_id: UUID | None = None):
    lang = data["language"].lower()
    if lang not in SUPPORTED_LANGUAGES:
        raise HTTPException(400, f"Unsupported language. Supported: {', '.join(sorted(SUPPORTED_LANGUAGES))}")

    source_code, file_path = _resolve_source(data)
    r = await db.execute(
        text("""
            INSERT INTO code_reviews (repository_url, branch, language, status, created_by, started_at)
            VALUES (:repo, :branch, :lang, 'running', :uid, NOW()) RETURNING id
        """),
        {
            "repo": data.get("repository_url") or file_path,
            "branch": data.get("branch", "main"),
            "lang": lang,
            "uid": str(user_id) if user_id else None,
        },
    )
    review_id = r.fetchone().id
    await publish_event("codereview.started", {"review_id": str(review_id), "language": lang})
    data = {**data, "source_code": source_code, "file_path": file_path}
    return await run_review(db, review_id, data, user_id)


async def run_review(db: AsyncSession, review_id: UUID, data: dict, user_id: UUID | None = None):
    code = data.get("source_code") or ""
    file_path = data.get("file_path") or "source"
    findings: list[dict] = []
    clone_path: Path | None = None

    try:
        if data.get("repository_url") and not code.strip():
            clone_path = _clone_repository(data["repository_url"], data.get("branch", "main"))
            findings = await _scan_directory(clone_path, data["language"])
        elif code.strip():
            findings = analyze_source(code, file_path, data["language"])
            if len(findings) <= 1 and findings[0].get("severity") == "info":
                findings = analyze_source(code, file_path, data["language"])

        static_only = [f for f in findings if f.get("severity") != "info"]
        if static_only or findings:
            try:
                llm = get_security_llm()
                summary = [
                    {
                        "title": f.get("title"),
                        "severity": f.get("severity"),
                        "file_path": f.get("file_path"),
                        "line": f.get("line_start"),
                        "category": f.get("category"),
                        "description": sanitize_for_llm(str(f.get("description") or ""), 300),
                    }
                    for f in (static_only or findings)[:30]
                ]
                system = (
                    "You are a senior application security engineer. Triage static/semgrep findings. "
                    "Return JSON with key 'findings' as a list of objects with: title, severity "
                    "(critical|high|medium|low|info), category, description, root_cause, line_start, "
                    "line_end, file_path, recommended_fix, owasp_category, cwe_id, cvss_score."
                )
                user_prompt = sanitize_for_llm(
                    f"Language: {data['language']}\nStatic findings summary:\n{json.dumps(summary)}"
                )
                result = await llm.generate_json(system, user_prompt)
                llm_findings = result.get("findings", [])
                if isinstance(llm_findings, dict):
                    llm_findings = [llm_findings]
                if llm_findings:
                    findings = await triage_findings([f for f in llm_findings if isinstance(f, dict)])
            except SecurityLLMConfigurationError as exc:
                if not static_only:
                    raise HTTPException(503, str(exc)) from exc
            except Exception:
                # If the local Ollama endpoint is temporarily unavailable/misconfigured,
                # keep the static findings and continue so API scans complete end-to-end.
                pass

        count = 0
        for f in findings:
            if not isinstance(f, dict):
                continue
            if f.get("severity") == "info" and count > 0:
                continue
            await db.execute(
                text("""
                    INSERT INTO code_review_findings (review_id, file_path, line_start, line_end, severity, category,
                        title, description, root_cause, recommended_fix, owasp_category, cwe_id, cvss_score, confidence_score)
                    VALUES (:rid, :fp, :ls, :le, :sev, :cat, :title, :desc, :root, :fix, :owasp, :cwe, :cvss, 0.9)
                """),
                {
                    "rid": str(review_id),
                    "fp": f.get("file_path", file_path),
                    "ls": f.get("line_start"),
                    "le": f.get("line_end"),
                    "sev": f.get("severity", "medium"),
                    "cat": f.get("category", "security"),
                    "title": str(f.get("title", "Security finding"))[:500],
                    "desc": f.get("description"),
                    "root": f.get("root_cause"),
                    "fix": f.get("recommended_fix") or f.get("remediation"),
                    "owasp": f.get("owasp_category"),
                    "cwe": normalize_cwe_id(f.get("cwe_id")),
                    "cvss": f.get("cvss_score"),
                },
            )
            count += 1

        await db.execute(
            text("UPDATE code_reviews SET status = 'completed', findings_count = :fc, completed_at = NOW() WHERE id = :id"),
            {"id": str(review_id), "fc": count},
        )
        await publish_event("codereview.completed", {"review_id": str(review_id), "findings": count})

        report_id = None
        try:
            report = await generate_codereview_executive_report(db, review_id, user_id)
            report_id = report["id"]
        except Exception:
            pass

        review = await get_review(db, review_id)
        if report_id:
            review["report_id"] = report_id
        return review
    finally:
        if clone_path and clone_path.exists():
            shutil.rmtree(clone_path, ignore_errors=True)


async def get_review(db: AsyncSession, review_id: UUID):
    r = await db.execute(
        text("""
            SELECT id, repository_url, branch, language, status::text, findings_count, started_at, completed_at, created_at
            FROM code_reviews WHERE id = :id
        """),
        {"id": str(review_id)},
    )
    row = r.fetchone()
    if not row:
        raise HTTPException(404, "Code review not found")
    return dict(row._mapping)


async def list_reviews(db: AsyncSession, limit=50, offset=0):
    r = await db.execute(
        text("""
            SELECT id, repository_url, branch, language, status::text, findings_count, created_at
            FROM code_reviews ORDER BY created_at DESC LIMIT :limit OFFSET :offset
        """),
        {"limit": limit, "offset": offset},
    )
    return [dict(row._mapping) for row in r.fetchall()]


async def list_findings(db: AsyncSession, review_id: UUID):
    r = await db.execute(
        text("""
            SELECT id, file_path, function_name, line_start, line_end, severity::text, category, title,
                   description, root_cause, recommended_fix, owasp_category, cwe_id, cvss_score, status::text, created_at
            FROM code_review_findings WHERE review_id = :rid ORDER BY severity, created_at DESC
        """),
        {"rid": str(review_id)},
    )
    return [dict(row._mapping) for row in r.fetchall()]
