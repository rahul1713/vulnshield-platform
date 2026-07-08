from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from vulnshield_common.auth import TokenPayload, require_permission
from vulnshield_common.database import get_db
from app.schemas import WebScanCreate, WebScanResponse
from app.services import web_scan_service

router = APIRouter(prefix="/web-scans", tags=["Web Scans"])


async def _run_scan_background(scan_id: UUID):
    from sqlalchemy import text
    from vulnshield_common.database import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        try:
            await web_scan_service.execute_web_scan(db, scan_id)
            await db.commit()
        except Exception as exc:
            await db.rollback()
            async with AsyncSessionLocal() as err_db:
                await err_db.execute(
                    text("UPDATE scans SET status = 'failed', error_message = :err WHERE id = :id"),
                    {"id": str(scan_id), "err": str(exc)[:500]},
                )
                await err_db.commit()


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
    return scan


@router.post("/{scan_id}/execute")
async def execute_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("scans:write")),
):
    """Trigger scan execution (used by scan-worker or manual retry)."""
    return await web_scan_service.execute_web_scan(db, scan_id)


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
    cfg_r = await db.execute(
        text("SELECT target_config FROM scans WHERE id = :id"),
        {"id": str(scan_id)},
    )
    row = cfg_r.fetchone()
    if not row:
        raise HTTPException(404, "Scan not found")
    cfg = row.target_config or {}
    base_url = cfg.get("target_url")
    if not base_url:
        raise HTTPException(400, "Scan missing target_url")
    depth = int(cfg.get("crawl_depth", 3))
    return await web_scan_service.crawl_target(db, scan_id, base_url, depth)
