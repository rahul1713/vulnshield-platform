"""Execute vulnerability scans and attach findings."""

from __future__ import annotations

import json
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from vulnshield_common.entity_reports import generate_scan_executive_report
from vulnshield_common.messaging import publish_event


async def execute_scan(db: AsyncSession, scan_id: UUID, user_id: UUID | None = None) -> dict:
    """Run scan logic: correlate vulnerabilities, complete scan, generate executive PDF."""
    scan_r = await db.execute(
        text("SELECT id, name, target_asset_id, scan_type::text FROM scans WHERE id = :id"),
        {"id": str(scan_id)},
    )
    scan = scan_r.fetchone()
    if not scan:
        raise ValueError("Scan not found")

    params: dict = {"sid": str(scan_id)}
    asset_clause = ""
    if scan.target_asset_id:
        asset_clause = "AND v.asset_id = :asset_id"
        params["asset_id"] = str(scan.target_asset_id)

    vuln_r = await db.execute(
        text(f"""
            SELECT v.id, v.severity::text FROM vulnerabilities v
            WHERE v.status NOT IN ('closed', 'false_positive') {asset_clause}
            ORDER BY v.cvss_score DESC NULLS LAST LIMIT 30
        """),
        params,
    )
    vulns = vuln_r.fetchall()

    crit = high = med = low = info = 0
    for v in vulns:
        await db.execute(
            text("UPDATE vulnerabilities SET scan_id = :sid WHERE id = :vid"),
            {"sid": str(scan_id), "vid": str(v.id)},
        )
        sev = v.severity
        if sev == "critical":
            crit += 1
        elif sev == "high":
            high += 1
        elif sev == "medium":
            med += 1
        elif sev == "low":
            low += 1
        else:
            info += 1

    total = len(vulns)
    await db.execute(
        text("""
            INSERT INTO scan_results (scan_id, asset_id, raw_data, processed_at)
            VALUES (:sid, :asset, CAST(:raw AS jsonb), NOW())
        """),
        {
            "sid": str(scan_id),
            "asset": str(scan.target_asset_id) if scan.target_asset_id else None,
            "raw": json.dumps({"findings_linked": total, "scan_type": scan.scan_type}),
        },
    )

    from app.services.scan_service import complete_scan

    result = await complete_scan(
        db,
        scan_id,
        {
            "findings_count": total,
            "critical_count": crit,
            "high_count": high,
            "medium_count": med,
            "low_count": low,
            "info_count": info,
        },
    )

    try:
        report = await generate_scan_executive_report(db, scan_id, user_id)
        await publish_event("scan.report.generated", {"scan_id": str(scan_id), "report_id": report["id"]})
        result["report_id"] = report["id"]
    except Exception:
        pass

    return result
