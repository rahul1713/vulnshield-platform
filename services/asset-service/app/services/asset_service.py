import json
from uuid import UUID
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from vulnshield_common.messaging import publish_event

async def list_assets(db: AsyncSession, limit=50, offset=0, filters: dict | None = None):
    q = """SELECT id, name, asset_type::text, status::text, host(ip_address) AS ip_address,
           hostname, criticality, business_unit, tags, last_seen, created_at FROM assets WHERE 1=1"""
    params = {"limit": limit, "offset": offset}
    if filters:
        if filters.get("asset_type"):
            q += " AND asset_type = :asset_type"; params["asset_type"] = filters["asset_type"]
        if filters.get("status"):
            q += " AND status = :status"; params["status"] = filters["status"]
        if filters.get("business_unit"):
            q += " AND business_unit = :bu"; params["bu"] = filters["business_unit"]
    q += " ORDER BY created_at DESC LIMIT :limit OFFSET :offset"
    r = await db.execute(text(q), params)
    return [dict(row._mapping) for row in r.fetchall()]

async def get_asset(db: AsyncSession, asset_id: UUID):
    r = await db.execute(text("""
        SELECT id, name, asset_type::text, status::text, host(ip_address) AS ip_address, hostname, fqdn,
               os_family, os_version, criticality, business_unit, owner_id, tags, metadata, last_seen, created_at
        FROM assets WHERE id = :id
    """), {"id": str(asset_id)})
    row = r.fetchone()
    if not row: raise HTTPException(404, "Asset not found")
    return dict(row._mapping)

async def create_asset(db: AsyncSession, data: dict, user_id: UUID | None = None):
    r = await db.execute(text("""
        INSERT INTO assets (name, asset_type, status, ip_address, hostname, fqdn, os_family, os_version,
            criticality, business_unit, owner_id, tags, metadata, discovered_at)
        VALUES (:name, :type, :status, CAST(:ip AS inet), :hostname, :fqdn, :osf, :osv, :crit, :bu,
            :owner, CAST(:tags AS jsonb), CAST(:meta AS jsonb), NOW()) RETURNING id
    """), {"name": data["name"], "type": data["asset_type"], "status": data.get("status", "active"),
        "ip": data.get("ip_address"), "hostname": data.get("hostname"), "fqdn": data.get("fqdn"),
        "osf": data.get("os_family"), "osv": data.get("os_version"), "crit": data.get("criticality", 3),
        "bu": data.get("business_unit"), "owner": str(data["owner_id"]) if data.get("owner_id") else None,
        "tags": json.dumps(data.get("tags", [])), "meta": json.dumps(data.get("metadata", {}))})
    aid = r.fetchone().id
    await db.execute(text("""
        INSERT INTO asset_history (asset_id, change_type, new_values, changed_by)
        VALUES (:aid, 'created', CAST(:vals AS jsonb), :uid)
    """), {"aid": str(aid), "vals": json.dumps(data), "uid": str(user_id) if user_id else None})
    await publish_event("asset.created", {"asset_id": str(aid), "name": data["name"]})
    return await get_asset(db, aid)

async def update_asset(db: AsyncSession, asset_id: UUID, data: dict, user_id: UUID | None = None):
    old = await get_asset(db, asset_id)
    fields, params = [], {"id": str(asset_id)}
    mapping = {"name":"name","status":"status","hostname":"hostname","criticality":"criticality","business_unit":"business_unit"}
    for k, col in mapping.items():
        if data.get(k) is not None:
            fields.append(f"{col} = :{k}"); params[k] = data[k]
    if data.get("ip_address") is not None:
        fields.append("ip_address = CAST(:ip AS inet)"); params["ip"] = data["ip_address"]
    if data.get("tags") is not None:
        fields.append("tags = CAST(:tags AS jsonb)"); params["tags"] = json.dumps(data["tags"])
    if fields:
        await db.execute(text(f"UPDATE assets SET {', '.join(fields)} WHERE id = :id"), params)
    await db.execute(text("""
        INSERT INTO asset_history (asset_id, change_type, old_values, new_values, changed_by)
        VALUES (:aid, 'updated', CAST(:old AS jsonb), CAST(:new AS jsonb), :uid)
    """), {"aid": str(asset_id), "old": json.dumps(old), "new": json.dumps(data),
           "uid": str(user_id) if user_id else None})
    return await get_asset(db, asset_id)

async def delete_asset(db: AsyncSession, asset_id: UUID):
    r = await db.execute(text("DELETE FROM assets WHERE id = :id RETURNING id"), {"id": str(asset_id)})
    if not r.fetchone(): raise HTTPException(404, "Asset not found")

async def search_assets(db: AsyncSession, query: dict, limit=50, offset=0):
    q = """SELECT id, name, asset_type::text, status::text, host(ip_address) AS ip_address,
           hostname, criticality, business_unit, tags, last_seen, created_at FROM assets WHERE 1=1"""
    params = {"limit": limit, "offset": offset}
    if query.get("q"):
        q += " AND (name ILIKE :q OR hostname ILIKE :q OR host(ip_address)::text ILIKE :q)"
        params["q"] = f"%{query['q']}%"
    for f in ["asset_type", "status", "business_unit"]:
        if query.get(f): q += f" AND {f} = :{f}"; params[f] = query[f]
    if query.get("criticality_min"): q += " AND criticality >= :cmin"; params["cmin"] = query["criticality_min"]
    if query.get("criticality_max"): q += " AND criticality <= :cmax"; params["cmax"] = query["criticality_max"]
    if query.get("tag"): q += " AND tags @> CAST(:tag AS jsonb)"; params["tag"] = json.dumps([query["tag"]])
    q += " ORDER BY criticality DESC, name LIMIT :limit OFFSET :offset"
    r = await db.execute(text(q), params)
    return [dict(row._mapping) for row in r.fetchall()]

async def discover_asset(db: AsyncSession, data: dict, user_id: UUID | None = None):
    name = data.get("hostname") or data.get("ip_range") or "discovered-asset"
    asset_data = {"name": name, "asset_type": data.get("asset_type", "linux_server"),
        "status": "pending_discovery", "ip_address": data.get("ip_range"), "hostname": data.get("hostname"),
        "tags": data.get("tags", ["auto-discovered"])}
    asset = await create_asset(db, asset_data, user_id)
    await publish_event("asset.discovered", {"asset_id": str(asset["id"]), "name": name})
    return asset

async def list_software(db: AsyncSession, asset_id: UUID):
    r = await db.execute(text("""
        SELECT id, name, version, vendor, cpe, package_manager, is_running, discovered_at
        FROM asset_software WHERE asset_id = :aid ORDER BY name
    """), {"aid": str(asset_id)})
    return [dict(row._mapping) for row in r.fetchall()]

async def add_software(db: AsyncSession, asset_id: UUID, data: dict):
    await get_asset(db, asset_id)
    r = await db.execute(text("""
        INSERT INTO asset_software (asset_id, name, version, vendor, cpe, package_manager, is_running)
        VALUES (:aid, :name, :ver, :vendor, :cpe, :pm, :running)
        ON CONFLICT (asset_id, name, version) DO UPDATE SET vendor=EXCLUDED.vendor, is_running=EXCLUDED.is_running
        RETURNING id, name, version, vendor, cpe, package_manager, is_running, discovered_at
    """), {"aid": str(asset_id), "name": data["name"], "ver": data.get("version"), "vendor": data.get("vendor"),
        "cpe": data.get("cpe"), "pm": data.get("package_manager"), "running": data.get("is_running", False)})
    return dict(r.fetchone()._mapping)

async def list_ports(db: AsyncSession, asset_id: UUID):
    r = await db.execute(text("""
        SELECT id, port, protocol, service_name, service_version, state, discovered_at
        FROM asset_ports WHERE asset_id = :aid ORDER BY port
    """), {"aid": str(asset_id)})
    return [dict(row._mapping) for row in r.fetchall()]

async def add_port(db: AsyncSession, asset_id: UUID, data: dict):
    await get_asset(db, asset_id)
    r = await db.execute(text("""
        INSERT INTO asset_ports (asset_id, port, protocol, service_name, service_version, state)
        VALUES (:aid, :port, :proto, :svc, :svcv, :state)
        ON CONFLICT (asset_id, port, protocol) DO UPDATE SET service_name=EXCLUDED.service_name, state=EXCLUDED.state
        RETURNING id, port, protocol, service_name, service_version, state, discovered_at
    """), {"aid": str(asset_id), "port": data["port"], "proto": data.get("protocol", "tcp"),
        "svc": data.get("service_name"), "svcv": data.get("service_version"), "state": data.get("state", "open")})
    return dict(r.fetchone()._mapping)

async def get_history(db: AsyncSession, asset_id: UUID, limit=50):
    r = await db.execute(text("""
        SELECT id, change_type, old_values, new_values, changed_by, created_at
        FROM asset_history WHERE asset_id = :aid ORDER BY created_at DESC LIMIT :limit
    """), {"aid": str(asset_id), "limit": limit})
    return [dict(row._mapping) for row in r.fetchall()]
