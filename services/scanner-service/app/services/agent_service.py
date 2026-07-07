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
    await db.execute(
        text("""
            UPDATE agents SET status = :status, last_heartbeat = NOW(),
                metadata = COALESCE(metadata, '{}'::jsonb) || CAST(:meta AS jsonb)
            WHERE agent_id = :aid
        """),
        {"aid": data["agent_id"], "status": data.get("status", "online"), "meta": json.dumps(data.get("metadata", {}))},
    )
    return await get_agent(db, data["agent_id"])


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
