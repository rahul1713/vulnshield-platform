from uuid import UUID
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from vulnshield_common.auth import TokenPayload, require_permission
from vulnshield_common.database import get_db
from app.schemas import CampaignCreate, CampaignResponse
from app.services import redteam_service

router = APIRouter(prefix="/campaigns", tags=["Red Team"])


@router.get("", response_model=list[CampaignResponse])
async def list_campaigns(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("scans:read")),
):
    return await redteam_service.list_campaigns(db, limit, offset)


@router.post("", response_model=CampaignResponse, status_code=201)
async def create_campaign(
    body: CampaignCreate,
    db: AsyncSession = Depends(get_db),
    user: TokenPayload = Depends(require_permission("scans:write")),
):
    from uuid import UUID as U

    return await redteam_service.create_campaign(db, body.model_dump(), U(user.user_id))


@router.get("/{campaign_id}")
async def get_campaign(
    campaign_id: UUID,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("scans:read")),
):
    return await redteam_service.get_campaign(db, campaign_id)


@router.get("/{campaign_id}/findings")
async def findings(
    campaign_id: UUID,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("scans:read")),
):
    return await redteam_service.list_findings(db, campaign_id)
