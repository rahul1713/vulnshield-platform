import json
from uuid import UUID
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from vulnshield_common.messaging import publish_event


async def list_scans(db: AsyncSession, limit=50, offset=0, scan_type: str | None = None, status: str | None = None):
    q = """SELECT id, name, scan_type::text, status::text, target_asset_id, findings_count,
           critical_count, high_count, medium_count, low_count, info_count,
           started_at, completed_at, created_at FROM scans WHERE 1=1"""
    params: dict = {"limit": limit, "offset": offset}
    if scan_type:
        q += " AND scan_type = :stype"
        params["stype"] = scan_type
    if status:
        q += " AND status = :status"
        params["status"] = status
    q += " ORDER BY created_at DESC LIMIT :limit OFFSET :offset"
    r = await db.execute(text(q), params)
    return [dict(row._mapping) for row in r.fetchall()]


async def get_scan(db: AsyncSession, scan_id: UUID):
    r = await db.execute(
        text("""
            SELECT id, name, scan_type::text, status::text, target_asset_id, target_config,
                   findings_count, critical_count, high_count, medium_count, low_count, info_count,
                   started_at, completed_at, duration_seconds, error_message, created_at
            FROM scans WHERE id = :id
        """),
        {"id": str(scan_id)},
    )
    row = r.fetchone()
    if not row:
        raise HTTPException(404, "Scan not found")
    return dict(row._mapping)


async def create_scan(db: AsyncSession, data: dict, user_id: UUID | None = None):
    r = await db.execute(
        text("""
            INSERT INTO scans (name, scan_type, target_asset_id, target_config, schedule_cron, created_by)
            VALUES (:name, :stype, :asset, CAST(:cfg AS jsonb), :cron, :uid)
            RETURNING id
        """),
        {
            "name": data["name"],
            "stype": data["scan_type"],
            "asset": str(data["target_asset_id"]) if data.get("target_asset_id") else None,
            "cfg": json.dumps(data.get("target_config", {})),
            "cron": data.get("schedule_cron"),
            "uid": str(user_id) if user_id else None,
        },
    )
    scan_id = r.fetchone().id
    await publish_event("scan.created", {"scan_id": str(scan_id), "scan_type": data["scan_type"]})
    return await get_scan(db, scan_id)


async def update_scan(db: AsyncSession, scan_id: UUID, data: dict):
    await get_scan(db, scan_id)
    fields, params = [], {"id": str(scan_id)}
    for key, col in {"name": "name", "status": "status", "error_message": "error_message"}.items():
        if data.get(key) is not None:
            fields.append(f"{col} = :{key}")
            params[key] = data[key]
    if fields:
        await db.execute(text(f"UPDATE scans SET {', '.join(fields)} WHERE id = :id"), params)
    return await get_scan(db, scan_id)


async def cancel_scan(db: AsyncSession, scan_id: UUID):
    return await update_scan(db, scan_id, {"status": "cancelled"})


async def start_scan(db: AsyncSession, scan_id: UUID):
    await db.execute(
        text("UPDATE scans SET status = 'running', started_at = NOW() WHERE id = :id"),
        {"id": str(scan_id)},
    )
    await publish_event("scan.started", {"scan_id": str(scan_id)})
    return await get_scan(db, scan_id)


async def complete_scan(db: AsyncSession, scan_id: UUID, counts: dict | None = None):
    counts = counts or {}
    await db.execute(
        text("""
            UPDATE scans SET status = 'completed', completed_at = NOW(),
                duration_seconds = EXTRACT(EPOCH FROM (NOW() - started_at))::int,
                findings_count = :total, critical_count = :crit, high_count = :high,
                medium_count = :med, low_count = :low, info_count = :info
            WHERE id = :id
        """),
        {
            "id": str(scan_id),
            "total": counts.get("findings_count", 0),
            "crit": counts.get("critical_count", 0),
            "high": counts.get("high_count", 0),
            "med": counts.get("medium_count", 0),
            "low": counts.get("low_count", 0),
            "info": counts.get("info_count", 0),
        },
    )
    await publish_event("scan.completed", {"scan_id": str(scan_id)})
    return await get_scan(db, scan_id)
