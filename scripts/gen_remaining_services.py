#!/usr/bin/env python3
"""Generate remaining VulnShield microservices."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
created: list[str] = []

def w(rel: str, content: str):
    p = ROOT / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content.rstrip() + "\n")
    created.append(rel)

def df(svc: str, port: int):
    w(f"services/{svc}/Dockerfile", f"""FROM python:3.11-slim
WORKDIR /app
COPY shared/python /shared/python
RUN pip install --no-cache-dir /shared/python
COPY services/{svc}/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY services/{svc}/app /app/app
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "{port}"]""")

def main_py(svc: str, title: str, desc: str, routes: list[str], port: int):
    ri = "\n".join(f"from app.routes import {r}" for r in routes)
    inc = "\n".join(f'app.include_router({r}.router, prefix="/api/v1")' for r in routes)
    w(f"services/{svc}/app/main.py", f'''"""{title}."""
from contextlib import asynccontextmanager
import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import make_asgi_app
from vulnshield_common.config import get_settings
{ri}
logger = structlog.get_logger()
settings = get_settings()

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("service_starting", service="{svc}")
    yield
    logger.info("service_stopping", service="{svc}")

app = FastAPI(title="{title}", description="{desc}", version="1.0.0", lifespan=lifespan,
    docs_url="/docs", redoc_url="/redoc", openapi_url="/openapi.json")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"])
{inc}
app.mount("/metrics", make_asgi_app())

@app.get("/health", tags=["Health"])
async def health():
    return {{"status": "healthy", "service": "{title}", "port": {port}}}

@app.get("/", tags=["Health"])
async def root():
    return {{"service": "{title}", "docs": "/docs"}}''')

def tests(svc: str, title: str):
    w(f"services/{svc}/tests/conftest.py", '''import pytest
from httpx import ASGITransport, AsyncClient
from app.main import app

@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c''')
    w(f"services/{svc}/tests/test_health.py", f'''import pytest

@pytest.mark.asyncio
async def test_health(client):
    r = await client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "healthy"
    assert r.json()["service"] == "{title}"''')

# ==================== ASSET SERVICE ====================
df("asset-service", 8002)
w("services/asset-service/requirements.txt", "vulnshield-common\npytest>=8.0.0\npytest-asyncio>=0.23.0\nhttpx>=0.26.0")
main_py("asset-service", "VulnShield Asset Service", "Asset CRUD, discovery, software inventory, ports, search, history",
        ["assets"], 8002)
tests("asset-service", "VulnShield Asset Service")

w("services/asset-service/app/schemas.py", '''from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, Field

class AssetCreate(BaseModel):
    name: str
    asset_type: str
    status: str = "active"
    ip_address: str | None = None
    hostname: str | None = None
    fqdn: str | None = None
    os_family: str | None = None
    os_version: str | None = None
    criticality: int = Field(default=3, ge=1, le=5)
    business_unit: str | None = None
    owner_id: UUID | None = None
    tags: list[str] = []
    metadata: dict = {}

class AssetUpdate(BaseModel):
    name: str | None = None
    status: str | None = None
    ip_address: str | None = None
    hostname: str | None = None
    criticality: int | None = Field(default=None, ge=1, le=5)
    business_unit: str | None = None
    owner_id: UUID | None = None
    tags: list[str] | None = None
    metadata: dict | None = None

class AssetResponse(BaseModel):
    id: UUID
    name: str
    asset_type: str
    status: str
    ip_address: str | None
    hostname: str | None
    criticality: int
    business_unit: str | None
    tags: list | None
    last_seen: datetime | None
    created_at: datetime

class SoftwareCreate(BaseModel):
    name: str
    version: str | None = None
    vendor: str | None = None
    cpe: str | None = None
    package_manager: str | None = None
    is_running: bool = False

class PortCreate(BaseModel):
    port: int = Field(ge=1, le=65535)
    protocol: str = "tcp"
    service_name: str | None = None
    service_version: str | None = None
    state: str = "open"

class DiscoveryRequest(BaseModel):
    ip_range: str | None = None
    hostname: str | None = None
    asset_type: str = "linux_server"
    tags: list[str] = []

class SearchQuery(BaseModel):
    q: str | None = None
    asset_type: str | None = None
    status: str | None = None
    criticality_min: int | None = None
    criticality_max: int | None = None
    business_unit: str | None = None
    tag: str | None = None''')

w("services/asset-service/app/services/asset_service.py", '''import json
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
    return [dict(row._mapping) for row in r.fetchall()]''')

w("services/asset-service/app/routes/assets.py", '''from uuid import UUID
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from vulnshield_common.auth import TokenPayload, require_permission
from vulnshield_common.database import get_db
from app.schemas import AssetCreate, AssetResponse, AssetUpdate, DiscoveryRequest, PortCreate, SearchQuery, SoftwareCreate
from app.services import asset_service

router = APIRouter(prefix="/assets", tags=["Assets"])

@router.get("", response_model=list[AssetResponse])
async def list_assets(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
    asset_type: str | None = None, status: str | None = None, db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("assets:read"))):
    return await asset_service.list_assets(db, limit, offset, {"asset_type": asset_type, "status": status})

@router.post("/search", response_model=list[AssetResponse])
async def search(body: SearchQuery, limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db), _: TokenPayload = Depends(require_permission("assets:read"))):
    return await asset_service.search_assets(db, body.model_dump(exclude_none=True), limit, offset)

@router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset(asset_id: UUID, db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("assets:read"))):
    return await asset_service.get_asset(db, asset_id)

@router.post("", response_model=AssetResponse, status_code=201)
async def create_asset(body: AssetCreate, db: AsyncSession = Depends(get_db),
    user: TokenPayload = Depends(require_permission("assets:write"))):
    return await asset_service.create_asset(db, body.model_dump(), UUID(user.user_id))

@router.put("/{asset_id}", response_model=AssetResponse)
async def update_asset(asset_id: UUID, body: AssetUpdate, db: AsyncSession = Depends(get_db),
    user: TokenPayload = Depends(require_permission("assets:write"))):
    return await asset_service.update_asset(db, asset_id, body.model_dump(exclude_unset=True), UUID(user.user_id))

@router.delete("/{asset_id}", status_code=204)
async def delete_asset(asset_id: UUID, db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("assets:write"))):
    await asset_service.delete_asset(db, asset_id)

@router.post("/discover", response_model=AssetResponse, status_code=201)
async def discover(body: DiscoveryRequest, db: AsyncSession = Depends(get_db),
    user: TokenPayload = Depends(require_permission("assets:write"))):
    return await asset_service.discover_asset(db, body.model_dump(), UUID(user.user_id))

@router.get("/{asset_id}/software")
async def list_software(asset_id: UUID, db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("assets:read"))):
    return await asset_service.list_software(db, asset_id)

@router.post("/{asset_id}/software", status_code=201)
async def add_software(asset_id: UUID, body: SoftwareCreate, db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("assets:write"))):
    return await asset_service.add_software(db, asset_id, body.model_dump())

@router.get("/{asset_id}/ports")
async def list_ports(asset_id: UUID, db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("assets:read"))):
    return await asset_service.list_ports(db, asset_id)

@router.post("/{asset_id}/ports", status_code=201)
async def add_port(asset_id: UUID, body: PortCreate, db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("assets:write"))):
    return await asset_service.add_port(db, asset_id, body.model_dump())

@router.get("/{asset_id}/history")
async def history(asset_id: UUID, limit: int = Query(50, ge=1, le=200), db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("assets:read"))):
    return await asset_service.get_history(db, asset_id, limit)''')

print("Asset service done")
