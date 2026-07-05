from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from vulnshield_common.auth import TokenPayload, require_permission
from vulnshield_common.database import get_db

from app.schemas import RoleCreate, RoleResponse, RoleUpdate, UserCreate, UserResponse, UserUpdate
from app.services import audit_service, role_service, user_service

router = APIRouter(prefix="/users", tags=["Users"])


@router.get("", response_model=list[UserResponse])
async def list_users(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("users:read")),
):
    return await user_service.list_users(db, limit, offset)


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("users:read")),
):
    return await user_service.get_user(db, user_id)


@router.post("", response_model=UserResponse, status_code=201)
async def create_user(
    body: UserCreate,
    db: AsyncSession = Depends(get_db),
    actor: TokenPayload = Depends(require_permission("users:write")),
):
    user = await user_service.create_user(db, body.model_dump())
    await audit_service.log_audit(db, UUID(actor.user_id), "user.create", "user", user["id"],
                                   details={"email": body.email})
    return user


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: UUID,
    body: UserUpdate,
    db: AsyncSession = Depends(get_db),
    actor: TokenPayload = Depends(require_permission("users:write")),
):
    user = await user_service.update_user(db, user_id, body.model_dump(exclude_unset=True))
    await audit_service.log_audit(db, UUID(actor.user_id), "user.update", "user", user_id)
    return user


@router.delete("/{user_id}", status_code=204)
async def delete_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor: TokenPayload = Depends(require_permission("users:write")),
):
    await user_service.delete_user(db, user_id)
    await audit_service.log_audit(db, UUID(actor.user_id), "user.delete", "user", user_id)
