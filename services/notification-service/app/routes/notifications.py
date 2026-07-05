from uuid import UUID
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from vulnshield_common.auth import TokenPayload, require_permission
from vulnshield_common.database import get_db
from app.schemas import NotificationCreate, NotificationResponse, NotificationRuleCreate
from app.services import notification_service

router = APIRouter(prefix="/notifications", tags=["Notifications"])


@router.get("", response_model=list[NotificationResponse])
async def list_notifications(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    channel: str | None = None,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("notifications:read")),
):
    return await notification_service.list_notifications(db, limit, offset, channel)


@router.post("", response_model=NotificationResponse, status_code=201)
async def send(
    body: NotificationCreate,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("notifications:write")),
):
    return await notification_service.send_notification(db, body.model_dump())


@router.get("/{notification_id}", response_model=NotificationResponse)
async def get_notification(
    notification_id: UUID,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("notifications:read")),
):
    return await notification_service.get_notification(db, notification_id)


@router.post("/rules", status_code=201)
async def create_rule(
    body: NotificationRuleCreate,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("notifications:write")),
):
    return await notification_service.create_rule(db, body.model_dump())


@router.get("/rules/list")
async def list_rules(
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("notifications:read")),
):
    return await notification_service.list_rules(db)
