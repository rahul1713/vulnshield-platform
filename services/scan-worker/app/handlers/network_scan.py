"""Handle scan.started and scan.agentless.queued events with nmap."""

from __future__ import annotations

import json
from uuid import UUID

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from vulnshield_common.messaging import publish_event
from vulnshield_common.scan_engines import nmap_to_vulnerabilities, run_nmap
from vulnshield_common.scan_sandbox import is_allowed_scan_target, sanitize_log_text, truncate_for_storage

logger = structlog.get_logger()


async def _resolve_target(db: AsyncSession, scan_id: UUID, config: dict | None) -> tuple[str | None, UUID | None]:
    cfg = config or {}
    target = cfg.get("target") or cfg.get("host") or cfg.get("ip_address") or cfg.get("hostname")

    row = await db.execute(
        text("SELECT target_asset_id, target_config FROM scans WHERE id = :id"),
        {"id": str(scan_id)},
    )
    scan = row.fetchone()
    if not scan:
        return None, None

    asset_id = scan.target_asset_id
    merged_cfg = {**(scan.target_config or {}), **cfg}
    target = target or merged_cfg.get("target") or merged_cfg.get("host") or merged_cfg.get("ip_address")

    if not target and asset_id:
        asset_row = await db.execute(
            text("SELECT host(ip_address) AS ip_address, hostname, fqdn FROM assets WHERE id = :id"),
            {"id": str(asset_id)},
        )
        asset = asset_row.fetchone()
        if asset:
            target = asset.ip_address or asset.hostname or asset.fqdn

    return target, asset_id


def _severity_for_port(port: int, service: str | None) -> str:
    risky_ports = {21, 22, 23, 25, 110, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 27017}
    if port in risky_ports:
        return "high"
    if service in ("http", "https", "ssl", "http-proxy"):
        return "medium"
    return "low"


async def handle_network_scan(db: AsyncSession, payload: dict) -> None:
    scan_id = UUID(payload["scan_id"])
    config = payload.get("config") or {}

    status_row = await db.execute(
        text("SELECT status::text, scan_type::text FROM scans WHERE id = :id"),
        {"id": str(scan_id)},
    )
    scan_meta = status_row.fetchone()
    if not scan_meta:
        logger.warning("scan_not_found", scan_id=str(scan_id))
        return
    if scan_meta.status in ("completed", "cancelled", "failed"):
        logger.info("scan_skip_terminal", scan_id=str(scan_id), status=scan_meta.status)
        return

    target, asset_id = await _resolve_target(db, scan_id, config)
    if not target:
        await db.execute(
            text("UPDATE scans SET status = 'failed', error_message = :err, completed_at = NOW() WHERE id = :id"),
            {"id": str(scan_id), "err": "No scan target resolved from config or asset"},
        )
        await publish_event("scan.completed", {"scan_id": str(scan_id), "error": "missing_target"})
        return

    if not is_allowed_scan_target(target):
        await db.execute(
            text("UPDATE scans SET status = 'failed', error_message = :err, completed_at = NOW() WHERE id = :id"),
            {"id": str(scan_id), "err": "Target not allowed in sandbox mode"},
        )
        await publish_event("scan.completed", {"scan_id": str(scan_id), "error": "target_blocked"})
        return

    if not asset_id:
        is_ip = _looks_like_ip(target)
        asset_row = await db.execute(
            text("""
                INSERT INTO assets (name, asset_type, ip_address, hostname, status)
                VALUES (
                    :name, 'ip_range',
                    CASE WHEN :is_ip THEN CAST(:target AS inet) ELSE NULL END,
                    CASE WHEN :is_ip THEN NULL ELSE :target END,
                    'active'
                )
                RETURNING id
            """),
            {"name": f"scan-target-{scan_id}", "target": target, "is_ip": is_ip},
        )
        asset_id = asset_row.fetchone().id
        await db.execute(
            text("UPDATE scans SET target_asset_id = :aid WHERE id = :id"),
            {"aid": str(asset_id), "id": str(scan_id)},
        )

    vuln_findings: list[dict] = []
    error_msg: str | None = None
    nmap_result: dict = {}
    try:
        nmap_result = await run_nmap(target)
        vuln_findings = nmap_to_vulnerabilities(nmap_result, str(asset_id))
    except Exception as exc:
        error_msg = sanitize_log_text(str(exc), 500)
        logger.error("nmap_scan_failed", scan_id=str(scan_id), target=target, error=error_msg)

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for host in nmap_result.get("hosts", []):
        for port_info in host.get("ports", []):
            if port_info.get("state") != "open":
                continue
            port = port_info["port"]
            service = port_info.get("service") or "unknown"
            await db.execute(
                text("""
                    INSERT INTO asset_ports (asset_id, port, protocol, service_name, service_version, state)
                    VALUES (:aid, :port, :proto, :svc, :ver, 'open')
                    ON CONFLICT (asset_id, port, protocol) DO UPDATE
                    SET service_name = EXCLUDED.service_name, service_version = EXCLUDED.service_version
                """),
                {
                    "aid": str(asset_id),
                    "port": port,
                    "proto": port_info.get("protocol", "tcp"),
                    "svc": service,
                    "ver": port_info.get("version"),
                },
            )

    for f in vuln_findings:
        sev = _severity_for_port(f.get("port") or 0, f.get("affected_software"))
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        await db.execute(
            text("""
                INSERT INTO vulnerabilities (
                    asset_id, scan_id, title, description, severity, port, protocol,
                    affected_software, affected_version, proof, remediation, category, status, metadata
                ) VALUES (
                    :aid, :sid, :title, :desc, :sev, :port, :proto,
                    :sw, :ver, :proof, :rem, 'network', 'open', CAST(:meta AS jsonb)
                )
            """),
            {
                "aid": str(asset_id),
                "sid": str(scan_id),
                "title": f.get("title", "Open port")[:500],
                "desc": truncate_for_storage(f.get("description")),
                "sev": sev,
                "port": f.get("port"),
                "proto": f.get("protocol", "tcp"),
                "sw": f.get("affected_software"),
                "ver": f.get("affected_version"),
                "proof": truncate_for_storage(f.get("proof")),
                "rem": "Close unused ports or restrict access via firewall rules.",
                "meta": json.dumps(f.get("metadata") or {"engine": "nmap"}),
            },
        )

    total = len(vuln_findings)
    status = "failed" if error_msg and total == 0 else "completed"
    await db.execute(
        text("""
            UPDATE scans SET status = :status, findings_count = :total,
                critical_count = :crit, high_count = :high, medium_count = :med,
                low_count = :low, info_count = :info,
                completed_at = NOW(), error_message = :err,
                duration_seconds = EXTRACT(EPOCH FROM (NOW() - COALESCE(started_at, created_at)))::int
            WHERE id = :id
        """),
        {
            "id": str(scan_id),
            "status": status,
            "total": total,
            "crit": sev_counts["critical"],
            "high": sev_counts["high"],
            "med": sev_counts["medium"],
            "low": sev_counts["low"],
            "info": sev_counts["info"],
            "err": error_msg,
        },
    )

    await db.execute(
        text("""
            INSERT INTO scan_results (scan_id, asset_id, raw_data, processed_at)
            VALUES (:sid, :aid, CAST(:raw AS jsonb), NOW())
        """),
        {
            "sid": str(scan_id),
            "aid": str(asset_id),
            "raw": json.dumps({"engine": "nmap", "target": target, "open_ports": total}),
        },
    )

    await publish_event("scan.completed", {"scan_id": str(scan_id), "findings": total})
    logger.info("scan_completed", scan_id=str(scan_id), findings=total, status=status)


def _looks_like_ip(value: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(value.split("/")[0])
        return True
    except ValueError:
        return False
