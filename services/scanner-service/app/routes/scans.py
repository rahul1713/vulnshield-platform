from uuid import UUID
from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from vulnshield_common.auth import TokenPayload, require_permission
from vulnshield_common.database import get_db
from app.schemas import AgentlessScanRequest, ScanCreate, ScanResponse, ScanUpdate
from app.services import scan_service

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.get("", response_model=list[ScanResponse])
async def list_scans(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    scan_type: str | None = None,
    status: str | None = None,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("scans:read")),
):
    return await scan_service.list_scans(db, limit, offset, scan_type, status)


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("scans:read")),
):
    return await scan_service.get_scan(db, scan_id)


@router.post("", response_model=ScanResponse, status_code=201)
async def create_scan(
    body: ScanCreate,
    db: AsyncSession = Depends(get_db),
    user: TokenPayload = Depends(require_permission("scans:write")),
):
    return await scan_service.create_scan(db, body.model_dump(), UUID(user.user_id))


@router.patch("/{scan_id}", response_model=ScanResponse)
async def update_scan(
    scan_id: UUID,
    body: ScanUpdate,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("scans:write")),
):
    return await scan_service.update_scan(db, scan_id, body.model_dump(exclude_unset=True))


@router.post("/{scan_id}/start", response_model=ScanResponse)
async def start_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("scans:write")),
):
    return await scan_service.start_scan(db, scan_id)


@router.post("/{scan_id}/cancel", response_model=ScanResponse)
async def cancel_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("scans:write")),
):
    return await scan_service.cancel_scan(db, scan_id)


@router.post("/{scan_id}/correlate")
async def correlate(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("scans:write")),
):
    from app.services import cve_service

    return await cve_service.correlate_scan(db, scan_id)


@router.post("/{scan_id}/ai-analyze")
async def ai_analyze(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("scans:write")),
):
    """AI vulnerability analysis — local Ollama Qwen 3.6 only."""
    from app.services import ai_vuln_service

    return await ai_vuln_service.ai_analyze_scan(db, scan_id)


@router.post("/agentless", response_model=ScanResponse, status_code=201)
async def agentless_scan(
    body: AgentlessScanRequest,
    db: AsyncSession = Depends(get_db),
    user: TokenPayload = Depends(require_permission("scans:write")),
):
    from app.services import agentless_service

    return await agentless_service.queue_agentless_scan(db, body.model_dump(), UUID(user.user_id))
