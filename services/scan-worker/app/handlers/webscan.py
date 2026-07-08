"""Handle webscan.started events with nuclei + httpx."""

from __future__ import annotations

import json
from uuid import UUID

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from vulnshield_common.messaging import publish_event
from vulnshield_common.scan_engines import httpx_probe, nuclei_to_web_finding, run_nuclei
from vulnshield_common.scan_sandbox import is_allowed_scan_target, normalize_cwe_id, sanitize_log_text, truncate_for_storage

logger = structlog.get_logger()


def _count_severities(findings: list[dict]) -> dict[str, int]:
    counts = {"critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0, "info_count": 0}
    for f in findings:
        sev = f.get("severity", "info")
        if sev == "critical":
            counts["critical_count"] += 1
        elif sev in counts:
            counts[f"{sev}_count"] += 1
    return counts


async def handle_webscan_started(db: AsyncSession, payload: dict) -> None:
    scan_id = UUID(payload["scan_id"])
    url = payload.get("url")

    row = await db.execute(
        text("SELECT id, status::text, target_config FROM scans WHERE id = :id AND scan_type = 'web_app'"),
        {"id": str(scan_id)},
    )
    scan = row.fetchone()
    if not scan:
        logger.warning("webscan_not_found", scan_id=str(scan_id))
        return
    if scan.status in ("completed", "cancelled", "failed"):
        logger.info("webscan_skip_terminal", scan_id=str(scan_id), status=scan.status)
        return

    cfg = scan.target_config or {}
    target_url = url or cfg.get("target_url")
    if not target_url:
        await db.execute(
            text("UPDATE scans SET status = 'failed', error_message = :err, completed_at = NOW() WHERE id = :id"),
            {"id": str(scan_id), "err": "Missing target_url in scan config"},
        )
        await publish_event("webscan.completed", {"scan_id": str(scan_id), "findings": 0, "error": "missing_target"})
        return

    if not is_allowed_scan_target(target_url):
        await db.execute(
            text("UPDATE scans SET status = 'failed', error_message = :err, completed_at = NOW() WHERE id = :id"),
            {"id": str(scan_id), "err": "Target not allowed in sandbox mode"},
        )
        await publish_event("webscan.completed", {"scan_id": str(scan_id), "findings": 0, "error": "target_blocked"})
        return

    all_findings: list[dict] = []
    error_msg: str | None = None

    try:
        raw_nuclei = await run_nuclei(target_url)
        for item in raw_nuclei:
            all_findings.append(nuclei_to_web_finding(item, target_url))
        probe = await httpx_probe(target_url)
        if probe.get("status_code", 0) >= 400:
            all_findings.append({
                "url": target_url,
                "vulnerability_type": "http_probe",
                "owasp_category": "A05:2021-Security Misconfiguration",
                "severity": "low",
                "title": f"HTTP {probe.get('status_code')} response",
                "description": f"Probe returned status {probe.get('status_code')}",
                "proof": sanitize_log_text(str(probe.get("headers", {}))[:500]),
                "remediation": "Review HTTP error handling and security headers.",
            })
    except Exception as exc:
        error_msg = sanitize_log_text(str(exc), 500)
        logger.error("webscan_engine_failed", scan_id=str(scan_id), error=error_msg)

    inserted = 0
    for f in all_findings:
        await db.execute(
            text("""
                INSERT INTO web_scan_findings (
                    scan_id, url, vulnerability_type, owasp_category, severity, title,
                    description, proof, remediation, cwe_id, is_simulated
                ) VALUES (
                    :sid, :url, :vtype, :owasp, :sev, :title,
                    :desc, :proof, :rem, :cwe, FALSE
                )
            """),
            {
                "sid": str(scan_id),
                "url": f.get("url", target_url),
                "vtype": f.get("vulnerability_type", "web"),
                "owasp": f.get("owasp_category"),
                "sev": f.get("severity", "medium"),
                "title": str(f.get("title", "Web finding"))[:500],
                "desc": truncate_for_storage(f.get("description")),
                "proof": truncate_for_storage(f.get("proof")),
                "rem": truncate_for_storage(f.get("remediation")),
                "cwe": normalize_cwe_id(f.get("cwe_id")),
            },
        )
        inserted += 1

    counts = _count_severities(all_findings)
    status = "failed" if error_msg and inserted == 0 else "completed"
    await db.execute(
        text("""
            UPDATE scans SET status = :status, findings_count = :total,
                critical_count = :crit, high_count = :high, medium_count = :med,
                low_count = :low, info_count = :info,
                completed_at = NOW(), error_message = :err,
                duration_seconds = EXTRACT(EPOCH FROM (NOW() - started_at))::int
            WHERE id = :id
        """),
        {
            "id": str(scan_id),
            "status": status,
            "total": inserted,
            "crit": counts["critical_count"],
            "high": counts["high_count"],
            "med": counts["medium_count"],
            "low": counts["low_count"],
            "info": counts["info_count"],
            "err": error_msg,
        },
    )

    await db.execute(
        text("""
            INSERT INTO scan_results (scan_id, raw_data, processed_at)
            VALUES (:sid, CAST(:raw AS jsonb), NOW())
        """),
        {
            "sid": str(scan_id),
            "raw": json.dumps({
                "engine": "nuclei+httpx",
                "findings": inserted,
                "target_url": target_url,
            }),
        },
    )

    await publish_event("webscan.completed", {"scan_id": str(scan_id), "findings": inserted})
    logger.info("webscan_completed", scan_id=str(scan_id), findings=inserted, status=status)
