from uuid import UUID
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
    return await asset_service.get_history(db, asset_id, limit)
