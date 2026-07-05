import json
from uuid import UUID
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from vulnshield_common.llm import get_llm_provider
from vulnshield_common.messaging import publish_event

SUPPORTED_LANGUAGES = {"python", "javascript", "typescript", "java", "go", "csharp", "ruby", "php", "c", "cpp", "rust", "kotlin", "swift"}


async def create_review(db: AsyncSession, data: dict, user_id: UUID | None = None):
    lang = data["language"].lower()
    if lang not in SUPPORTED_LANGUAGES:
        raise HTTPException(400, f"Unsupported language. Supported: {', '.join(sorted(SUPPORTED_LANGUAGES))}")
    r = await db.execute(
        text("""
            INSERT INTO code_reviews (repository_url, branch, language, status, created_by, started_at)
            VALUES (:repo, :branch, :lang, 'running', :uid, NOW()) RETURNING id
        """),
        {
            "repo": data.get("repository_url"),
            "branch": data.get("branch", "main"),
            "lang": lang,
            "uid": str(user_id) if user_id else None,
        },
    )
    review_id = r.fetchone().id
    await publish_event("codereview.started", {"review_id": str(review_id), "language": lang})
    return await run_review(db, review_id, data)


async def run_review(db: AsyncSession, review_id: UUID, data: dict):
    llm = get_llm_provider()
    code = data.get("source_code") or f"# Sample {data['language']} code for review"
    file_path = data.get("file_path") or "main." + data["language"][:2]
    system = (
        "You are a senior application security engineer. Analyze code for vulnerabilities. "
        "Return JSON with key 'findings' as a list of objects with: title, severity (critical|high|medium|low|info), "
        "category, description, root_cause, line_start, line_end, recommended_fix, owasp_category, cwe_id, cvss_score."
    )
    user_prompt = f"Language: {data['language']}\nFile: {file_path}\n\n```\n{code[:8000]}\n```"
    result = await llm.generate_json(system, user_prompt)
    findings = result.get("findings", [])
    if isinstance(findings, dict):
        findings = [findings]
    count = 0
    for f in findings:
        if not isinstance(f, dict):
            continue
        await db.execute(
            text("""
                INSERT INTO code_review_findings (review_id, file_path, line_start, line_end, severity, category,
                    title, description, root_cause, recommended_fix, owasp_category, cwe_id, cvss_score, confidence_score)
                VALUES (:rid, :fp, :ls, :le, :sev, :cat, :title, :desc, :root, :fix, :owasp, :cwe, :cvss, 0.85)
            """),
            {
                "rid": str(review_id),
                "fp": file_path,
                "ls": f.get("line_start"),
                "le": f.get("line_end"),
                "sev": f.get("severity", "medium"),
                "cat": f.get("category", "security"),
                "title": f.get("title", "Security finding")[:500],
                "desc": f.get("description"),
                "root": f.get("root_cause"),
                "fix": f.get("recommended_fix"),
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
    return await get_review(db, review_id)


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
