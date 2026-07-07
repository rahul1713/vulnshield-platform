import os
from pathlib import Path
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from vulnshield_common.entity_reports import generate_codereview_executive_report
from vulnshield_common.llm import SecurityLLMConfigurationError, get_local_security_llm_provider
from vulnshield_common.messaging import publish_event
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


async def create_review(db: AsyncSession, data: dict, user_id: UUID | None = None):
    lang = data["language"].lower()
    if lang not in SUPPORTED_LANGUAGES:
        raise HTTPException(400, f"Unsupported language. Supported: {', '.join(sorted(SUPPORTED_LANGUAGES))}")

    source_code, file_path = _resolve_source(data)
    if not source_code.strip() and data.get("repository_url"):
        source_code = f"// Repository review requested: {data['repository_url']}\n// Clone and scan in CI pipeline."

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

    if code.strip():
        findings = analyze_source(code, file_path, data["language"])
        if len(findings) <= 1 and findings[0].get("severity") == "info":
            try:
                llm = get_local_security_llm_provider()
                system = (
                    "You are a senior application security engineer. Analyze code for vulnerabilities. "
                    "Return JSON with key 'findings' as a list of objects with: title, severity "
                    "(critical|high|medium|low|info), category, description, root_cause, line_start, "
                    "line_end, recommended_fix, owasp_category, cwe_id, cvss_score."
                )
                user_prompt = f"Language: {data['language']}\nFile: {file_path}\n\n```\n{code[:8000]}\n```"
                result = await llm.generate_json(system, user_prompt)
                llm_findings = result.get("findings", [])
                if isinstance(llm_findings, dict):
                    llm_findings = [llm_findings]
                if llm_findings:
                    findings = [f for f in llm_findings if isinstance(f, dict)]
            except (SecurityLLMConfigurationError, Exception):
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
                "cwe": f.get("cwe_id"),
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
