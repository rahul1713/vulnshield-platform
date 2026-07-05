from uuid import UUID
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from vulnshield_common.auth import TokenPayload, require_permission
from vulnshield_common.database import get_db
from app.schemas import WebScanCreate, WebScanResponse
from app.services import web_scan_service

router = APIRouter(prefix="/web-scans", tags=["Web Scans"])


@router.get("", response_model=list[WebScanResponse])
async def list_scans(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("scans:read")),
):
    return await web_scan_service.list_web_scans(db, limit, offset)


@router.post("", response_model=WebScanResponse, status_code=201)
async def create_scan(
    body: WebScanCreate,
    db: AsyncSession = Depends(get_db),
    user: TokenPayload = Depends(require_permission("scans:write")),
):
    from uuid import UUID as U

    scan = await web_scan_service.create_web_scan(db, body.model_dump(), U(user.user_id))
    await web_scan_service.crawl_target(db, scan["id"], body.target_url, body.crawl_depth)
    await web_scan_service.run_owasp_tests(db, scan["id"], body.active_tests)
    return await web_scan_service.get_web_scan(db, scan["id"])


@router.get("/{scan_id}", response_model=WebScanResponse)
async def get_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("scans:read")),
):
    return await web_scan_service.get_web_scan(db, scan_id)


@router.get("/{scan_id}/findings")
async def findings(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("scans:read")),
):
    return await web_scan_service.list_findings(db, scan_id)


@router.post("/{scan_id}/crawl")
async def crawl(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("scans:write")),
):
    cfg = await web_scan_service.get_web_scan(db, scan_id)
    return await web_scan_service.crawl_target(db, scan_id, "https://example.com", 3)
