from uuid import UUID
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from vulnshield_common.auth import TokenPayload, require_permission
from vulnshield_common.database import get_db
from app.schemas import RiskScoreRequest, RiskScoreResponse
from app.services import risk_service

router = APIRouter(prefix="/risk", tags=["Risk Engine"])


@router.get("/scores", response_model=list[RiskScoreResponse])
async def list_scores(
    entity_type: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("vulnerabilities:read")),
):
    return await risk_service.list_scores(db, entity_type, limit, offset)


@router.post("/calculate/vulnerability/{vulnerability_id}", response_model=RiskScoreResponse)
async def calc_vuln_risk(
    vulnerability_id: UUID,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("vulnerabilities:write")),
):
    return await risk_service.calculate_vulnerability_risk(db, vulnerability_id)


@router.post("/calculate/asset/{asset_id}", response_model=RiskScoreResponse)
async def calc_asset_risk(
    asset_id: UUID,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("vulnerabilities:write")),
):
    return await risk_service.calculate_asset_risk(db, asset_id)


@router.get("/scores/{entity_type}/{entity_id}", response_model=RiskScoreResponse)
async def get_score(
    entity_type: str,
    entity_id: UUID,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("vulnerabilities:read")),
):
    return await risk_service.get_latest_score(db, entity_type, entity_id)
