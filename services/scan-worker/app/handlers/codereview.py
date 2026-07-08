"""Handle codereview.started events with semgrep."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from vulnshield_common.messaging import publish_event
from vulnshield_common.scan_engines import run_semgrep
from vulnshield_common.scan_sandbox import sanitize_log_text, truncate_for_storage

logger = structlog.get_logger()

ALLOWED_CODE_ROOTS = ("/app/code", "/tmp/vulnshield", "/workspace", "/code")


async def handle_codereview_started(db: AsyncSession, payload: dict) -> None:
    review_id = UUID(payload["review_id"])

    row = await db.execute(
        text("SELECT id, status::text, repository_url FROM code_reviews WHERE id = :id"),
        {"id": str(review_id)},
    )
    review = row.fetchone()
    if not review:
        logger.warning("codereview_not_found", review_id=str(review_id))
        return
    if review.status == "completed":
        logger.info("codereview_skip_completed", review_id=str(review_id))
        return

    repo_path = review.repository_url or ""
    scan_dir: str | None = None
    if repo_path.startswith("/"):
        resolved = Path(repo_path).resolve()
        if any(str(resolved).startswith(root) for root in ALLOWED_CODE_ROOTS):
            if resolved.is_dir():
                scan_dir = str(resolved)
            elif resolved.is_file():
                scan_dir = str(resolved.parent)

    if not scan_dir:
        logger.info("codereview_no_local_path", review_id=str(review_id))
        return

    findings: list[dict] = []
    try:
        findings = await run_semgrep(scan_dir)
    except Exception as exc:
        logger.error("semgrep_failed", review_id=str(review_id), error=sanitize_log_text(str(exc)))
        return

    count = 0
    for f in findings:
        await db.execute(
            text("""
                INSERT INTO code_review_findings (
                    review_id, file_path, line_start, line_end, severity, category,
                    title, description, recommended_fix, owasp_category, cwe_id, confidence_score
                ) VALUES (
                    :rid, :fp, :ls, :le, :sev, :cat,
                    :title, :desc, :fix, :owasp, :cwe, 0.95
                )
            """),
            {
                "rid": str(review_id),
                "fp": f.get("file_path", "unknown"),
                "ls": f.get("line_start"),
                "le": f.get("line_end"),
                "sev": f.get("severity", "medium"),
                "cat": f.get("category", "security"),
                "title": str(f.get("title", "Semgrep finding"))[:500],
                "desc": truncate_for_storage(f.get("description")),
                "fix": truncate_for_storage(f.get("recommended_fix")),
                "owasp": f.get("owasp_category"),
                "cwe": f.get("cwe_id"),
            },
        )
        count += 1

    if count:
        await db.execute(
            text("""
                UPDATE code_reviews SET findings_count = findings_count + :fc WHERE id = :id
            """),
            {"id": str(review_id), "fc": count},
        )
        await publish_event("codereview.engine.completed", {"review_id": str(review_id), "findings": count})

    logger.info("codereview_semgrep_done", review_id=str(review_id), findings=count)
