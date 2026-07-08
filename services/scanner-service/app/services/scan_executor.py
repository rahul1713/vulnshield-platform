"""Execute vulnerability scans with real engines and CVE correlation."""

from __future__ import annotations

import json
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from vulnshield_common.entity_reports import generate_scan_executive_report
from vulnshield_common.messaging import publish_event
from vulnshield_common.scan_engines import (
    EngineUnavailableError,
    engines_status,
    nmap_to_vulnerabilities,
    run_nmap,
    run_nuclei,
)


async def _resolve_target(scan) -> str | None:
    cfg = scan.target_config or {}
    if cfg.get("target"):
        return str(cfg["target"])
    if cfg.get("hostname"):
        return str(cfg["hostname"])
    if cfg.get("ip_address"):
        return str(cfg["ip_address"])
    if scan.hostname:
        return scan.hostname
    if scan.ip_address:
        return str(scan.ip_address)
    return None


async def _insert_vulnerability(db: AsyncSession, scan_id: UUID, asset_id: UUID, finding: dict) -> str:
    sev = finding.get("severity", "info")
    if sev not in ("critical", "high", "medium", "low", "info"):
        sev = "medium"
    r = await db.execute(
        text("""
            INSERT INTO vulnerabilities (asset_id, scan_id, title, description, severity, category,
                affected_software, affected_version, port, protocol, proof, remediation, metadata)
            VALUES (:aid, :sid, :title, :desc, CAST(:sev AS severity), :cat, :sw, :ver, :port, :proto,
                :proof, :rem, CAST(:meta AS jsonb))
            RETURNING id, severity::text
        """),
        {
            "aid": str(asset_id),
            "sid": str(scan_id),
            "title": (finding.get("title") or "Scan finding")[:500],
            "desc": finding.get("description"),
            "sev": sev,
            "cat": finding.get("category", "scanner"),
            "sw": finding.get("affected_software"),
            "ver": finding.get("affected_version"),
            "port": finding.get("port"),
            "proto": finding.get("protocol"),
            "proof": finding.get("proof"),
            "rem": finding.get("remediation"),
            "meta": json.dumps(finding.get("metadata") or {"engine": finding.get("engine", "scanner")}),
        },
    )
    row = r.fetchone()
    return row.severity if row else sev


async def execute_scan(db: AsyncSession, scan_id: UUID, user_id: UUID | None = None) -> dict:
    """Run nmap/nuclei discovery, then CVE correlation as secondary step."""
    scan_r = await db.execute(
        text("""
            SELECT s.id, s.name, s.target_asset_id, s.scan_type::text, s.target_config,
                   a.hostname, host(a.ip_address) AS ip_address
            FROM scans s
            LEFT JOIN assets a ON s.target_asset_id = a.id
            WHERE s.id = :id
        """),
        {"id": str(scan_id)},
    )
    scan = scan_r.fetchone()
    if not scan:
        raise ValueError("Scan not found")

    target = await _resolve_target(scan)
    raw_results: dict = {"scan_type": scan.scan_type, "target": target, "engines": engines_status()}
    discoveries: list[dict] = []

    if target:
        try:
            if scan.scan_type in ("network", "agentless_ssh", "agentless_winrm", "agentless_smb", "agent"):
                if engines_status().get("nmap"):
                    nmap_result = await run_nmap(target)
                    raw_results["nmap"] = nmap_result
                    discoveries.extend(
                        nmap_to_vulnerabilities(nmap_result, str(scan.target_asset_id) if scan.target_asset_id else None)
                    )
            if scan.scan_type in ("network", "web_app") and engines_status().get("nuclei"):
                nuclei_hits = await run_nuclei(target if target.startswith("http") else f"http://{target}")
                raw_results["nuclei_count"] = len(nuclei_hits)
                for hit in nuclei_hits:
                    info = hit.get("info", {})
                    discoveries.append(
                        {
                            "title": info.get("name", hit.get("template-id", "Nuclei finding")),
                            "severity": (info.get("severity") or "medium").lower(),
                            "category": "nuclei",
                            "description": info.get("description"),
                            "proof": json.dumps(hit)[:2000],
                            "remediation": info.get("remediation"),
                            "metadata": {"engine": "nuclei", "template": hit.get("template-id")},
                        }
                    )
        except EngineUnavailableError as exc:
            raw_results["engine_error"] = str(exc)

    asset_id = scan.target_asset_id
    if asset_id:
        for finding in discoveries:
            await _insert_vulnerability(db, scan_id, asset_id, finding)

    crit = high = med = low = info = 0
    total = 0

    if scan.target_asset_id:
        try:
            from app.services import cve_service

            cve_result = await cve_service.correlate_scan(db, scan_id)
            raw_results["cve_correlation"] = cve_result
        except Exception as exc:
            raw_results["cve_correlation_error"] = str(exc)

    if scan.target_asset_id:
        count_r = await db.execute(
            text("""
                SELECT severity::text, COUNT(*) AS cnt FROM vulnerabilities
                WHERE scan_id = :sid GROUP BY severity
            """),
            {"sid": str(scan_id)},
        )
        crit = high = med = low = info = 0
        for row in count_r.fetchall():
            n = row.cnt
            if row.severity == "critical":
                crit = n
            elif row.severity == "high":
                high = n
            elif row.severity == "medium":
                med = n
            elif row.severity == "low":
                low = n
            else:
                info = n
        total = crit + high + med + low + info

    await db.execute(
        text("""
            INSERT INTO scan_results (scan_id, asset_id, raw_data, processed_at)
            VALUES (:sid, :asset, CAST(:raw AS jsonb), NOW())
        """),
        {
            "sid": str(scan_id),
            "asset": str(scan.target_asset_id) if scan.target_asset_id else None,
            "raw": json.dumps(raw_results, default=str),
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
