from uuid import UUID
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from vulnshield_common.auth import TokenPayload, require_permission
from vulnshield_common.database import get_db
from app.schemas import PatchCreate, PatchResponse
from app.services import patch_service

router = APIRouter(prefix="/patches", tags=["Patch Intelligence"])


@router.get("", response_model=list[PatchResponse])
async def list_patches(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    patch_available: bool | None = None,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("vulnerabilities:read")),
):
    return await patch_service.list_patches(db, limit, offset, patch_available)


@router.post("", response_model=PatchResponse, status_code=201)
async def create_patch(
    body: PatchCreate,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("vulnerabilities:write")),
):
    return await patch_service.create_patch(db, body.model_dump())


@router.get("/{patch_id}", response_model=PatchResponse)
async def get_patch(
    patch_id: UUID,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("vulnerabilities:read")),
):
    return await patch_service.get_patch(db, patch_id)


@router.get("/eol/{software_name}")
async def eol_check(
    software_name: str,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("vulnerabilities:read")),
):
    return await patch_service.check_eol(db, software_name)


@router.get("/advisories/list")
async def advisories(
    cve_id: str | None = None,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("vulnerabilities:read")),
):
    return await patch_service.get_advisories(db, cve_id)
