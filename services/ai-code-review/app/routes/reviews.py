from uuid import UUID
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from vulnshield_common.auth import TokenPayload, require_permission
from vulnshield_common.database import get_db
from app.schemas import CodeReviewCreate, CodeReviewResponse
from app.services import code_review_service

router = APIRouter(prefix="/reviews", tags=["Code Reviews"])


@router.get("", response_model=list[CodeReviewResponse])
async def list_reviews(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("scans:read")),
):
    return await code_review_service.list_reviews(db, limit, offset)


@router.post("", response_model=CodeReviewResponse, status_code=201)
async def create_review(
    body: CodeReviewCreate,
    db: AsyncSession = Depends(get_db),
    user: TokenPayload = Depends(require_permission("scans:write")),
):
    from uuid import UUID as U

    return await code_review_service.create_review(db, body.model_dump(), U(user.user_id))


@router.get("/{review_id}", response_model=CodeReviewResponse)
async def get_review(
    review_id: UUID,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("scans:read")),
):
    return await code_review_service.get_review(db, review_id)


@router.get("/{review_id}/findings")
async def findings(
    review_id: UUID,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("scans:read")),
):
    return await code_review_service.list_findings(db, review_id)
