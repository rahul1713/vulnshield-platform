import json
from uuid import UUID
from fastapi import HTTPException, Request
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from vulnshield_common.messaging import publish_event


async def list_agents(db: AsyncSession, limit=50, offset=0):
    r = await db.execute(
        text("""
            SELECT id, agent_id, asset_id, hostname, platform, version, status::text,
                   certificate_fingerprint, last_heartbeat, host(ip_address) AS ip_address, created_at
            FROM agents ORDER BY last_heartbeat DESC NULLS LAST LIMIT :limit OFFSET :offset
        """),
        {"limit": limit, "offset": offset},
    )
    return [dict(row._mapping) for row in r.fetchall()]


async def get_agent(db: AsyncSession, agent_id: str):
    r = await db.execute(
        text("""
            SELECT id, agent_id, asset_id, hostname, platform, version, status::text,
                   certificate_fingerprint, last_heartbeat, host(ip_address) AS ip_address, metadata, created_at
            FROM agents WHERE agent_id = :aid
        """),
        {"aid": agent_id},
    )
    row = r.fetchone()
    if not row:
        raise HTTPException(404, "Agent not found")
    return dict(row._mapping)


async def register_agent(db: AsyncSession, data: dict):
    r = await db.execute(
        text("""
            INSERT INTO agents (agent_id, asset_id, hostname, platform, version, status,
                certificate_fingerprint, ip_address, metadata)
            VALUES (:aid, :asset, :host, :plat, :ver, 'pending', :fp,
                CAST(:ip AS inet), CAST(:meta AS jsonb))
            ON CONFLICT (agent_id) DO UPDATE SET
                hostname = EXCLUDED.hostname, platform = EXCLUDED.platform, version = EXCLUDED.version,
                certificate_fingerprint = EXCLUDED.certificate_fingerprint, updated_at = NOW()
            RETURNING id, agent_id
        """),
        {
            "aid": data["agent_id"],
            "asset": str(data["asset_id"]) if data.get("asset_id") else None,
            "host": data.get("hostname"),
            "plat": data["platform"],
            "ver": data.get("version"),
            "fp": data.get("certificate_fingerprint"),
            "ip": data.get("ip_address"),
            "meta": json.dumps(data.get("metadata", {})),
        },
    )
    row = r.fetchone()
    await publish_event("agent.registered", {"agent_id": data["agent_id"]})
    return await get_agent(db, row.agent_id)


async def heartbeat(db: AsyncSession, data: dict):
    meta = dict(data.get("metadata") or {})
    if data.get("timestamp"):
        meta["last_heartbeat_ts"] = data["timestamp"]
    if data.get("ip_address"):
        meta["reported_ip"] = data["ip_address"]

    await db.execute(
        text("""
            UPDATE agents SET status = :status, last_heartbeat = NOW(),
                ip_address = COALESCE(CAST(:ip AS inet), ip_address),
                metadata = COALESCE(metadata, '{}'::jsonb) || CAST(:meta AS jsonb)
            WHERE agent_id = :aid
        """),
        {
            "aid": data["agent_id"],
            "status": data.get("status", "online"),
            "ip": data.get("ip_address"),
            "meta": json.dumps(meta),
        },
    )
    return await get_agent(db, data["agent_id"])


async def ingest_inventory(db: AsyncSession, agent_id: str, data: dict) -> dict:
    agent = await get_agent(db, agent_id)
    if data.get("agent_id") and data["agent_id"] != agent_id:
        raise HTTPException(400, "agent_id in path and body must match")

    inventory = data.get("inventory") or {}
    asset_id = agent.get("asset_id")

    if not asset_id:
        os_info = inventory.get("os_info") or {}
        hostname = agent.get("hostname") or os_info.get("hostname") or agent_id
        ip = agent.get("ip_address") or os_info.get("ip_address")
        r = await db.execute(
            text("""
                INSERT INTO assets (name, asset_type, status, hostname, ip_address, os_family, os_version,
                    kernel_version, last_seen, discovered_at)
                VALUES (:name, 'linux_server', 'active', :host, CAST(:ip AS inet), :osfam, :osver, :kernel, NOW(), NOW())
                RETURNING id
            """),
            {
                "name": hostname,
                "host": hostname,
                "ip": ip,
                "osfam": os_info.get("os_family") or os_info.get("distribution"),
                "osver": os_info.get("os_version") or os_info.get("version"),
                "kernel": (inventory.get("kernel") or {}).get("release"),
            },
        )
        asset_id = r.fetchone().id
        await db.execute(
            text("UPDATE agents SET asset_id = :asset, status = 'online', last_heartbeat = NOW() WHERE agent_id = :aid"),
            {"asset": str(asset_id), "aid": agent_id},
        )
    else:
        await db.execute(
            text("UPDATE assets SET last_seen = NOW(), updated_at = NOW() WHERE id = :id"),
            {"id": str(asset_id)},
        )

    sw_count = 0
    packages = (inventory.get("packages") or {}).get("packages") or []
    for pkg in packages[:5000]:
        if not isinstance(pkg, dict) or not pkg.get("name"):
            continue
        await db.execute(
            text("""
                INSERT INTO asset_software (asset_id, name, version, vendor, package_manager)
                VALUES (:aid, :name, :ver, :vendor, :pm)
                ON CONFLICT (asset_id, name, version) DO UPDATE SET
                    vendor = EXCLUDED.vendor, package_manager = EXCLUDED.package_manager, discovered_at = NOW()
            """),
            {
                "aid": str(asset_id),
                "name": pkg["name"][:255],
                "ver": (pkg.get("version") or "")[:100] or None,
                "vendor": (pkg.get("vendor") or "")[:255] or None,
                "pm": pkg.get("package_manager"),
            },
        )
        sw_count += 1

    port_count = 0
    ports = (inventory.get("open_ports") or {}).get("ports") or []
    for p in ports:
        if not isinstance(p, dict) or not p.get("port"):
            continue
        await db.execute(
            text("""
                INSERT INTO asset_ports (asset_id, port, protocol, state)
                VALUES (:aid, :port, :proto, :state)
                ON CONFLICT (asset_id, port, protocol) DO UPDATE SET state = EXCLUDED.state, discovered_at = NOW()
            """),
            {
                "aid": str(asset_id),
                "port": int(p["port"]),
                "proto": (p.get("protocol") or "tcp")[:10],
                "state": (p.get("state") or "open")[:20],
            },
        )
        port_count += 1

    await db.execute(
        text("""
            UPDATE agents SET metadata = COALESCE(metadata, '{}'::jsonb) || CAST(:meta AS jsonb),
                status = 'online', last_heartbeat = NOW() WHERE agent_id = :aid
        """),
        {
            "aid": agent_id,
            "meta": json.dumps({
                "last_inventory_at": data.get("collected_at"),
                "inventory_categories": list(inventory.keys()),
            }),
        },
    )
    await publish_event(
        "agent.inventory.ingested",
        {"agent_id": agent_id, "asset_id": str(asset_id), "software": sw_count, "ports": port_count},
    )
    return {
        "agent_id": agent_id,
        "asset_id": str(asset_id),
        "software_ingested": sw_count,
        "ports_ingested": port_count,
    }


def verify_mtls(request: Request, expected_fingerprint: str | None) -> bool:
    """Validate client certificate fingerprint. Fails closed in sandbox/production."""
    from vulnshield_common.config import get_settings
    from vulnshield_common.security import is_protected_environment

    settings = get_settings()
    if is_protected_environment(settings.environment):
        if not expected_fingerprint:
            return False
        client_fp = request.headers.get("X-Client-Cert-Fingerprint") or request.headers.get(
            "X-SSL-Client-Fingerprint"
        )
        return bool(client_fp and client_fp.lower() == expected_fingerprint.lower())

    if not expected_fingerprint:
        return True
    client_fp = request.headers.get("X-Client-Cert-Fingerprint") or request.headers.get(
        "X-SSL-Client-Fingerprint"
    )
    if not client_fp:
        return request.headers.get("X-MTLS-Optional", "").lower() == "true"
    return client_fp.lower() == expected_fingerprint.lower()
