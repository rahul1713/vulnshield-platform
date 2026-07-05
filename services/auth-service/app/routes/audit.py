from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from vulnshield_common.auth import TokenPayload, require_permission
from vulnshield_common.database import get_db

from app.schemas import AuditLogResponse
from app.services import audit_service

router = APIRouter(prefix="/audit-logs", tags=["Audit"])


@router.get("", response_model=list[AuditLogResponse])
async def list_audit_logs(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user_id: UUID | None = None,
    action: str | None = None,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("audit:read")),
):
    return await audit_service.list_audit_logs(db, limit, offset, user_id, action)
