from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from vulnshield_common.auth import TokenPayload, require_permission
from vulnshield_common.database import get_db

from app.schemas import RoleCreate, RoleResponse, RoleUpdate
from app.services import audit_service, role_service

router = APIRouter(prefix="/roles", tags=["Roles"])


@router.get("", response_model=list[RoleResponse])
async def list_roles(
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("users:read")),
):
    return await role_service.list_roles(db)


@router.get("/{role_id}", response_model=RoleResponse)
async def get_role(
    role_id: UUID,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("users:read")),
):
    return await role_service.get_role(db, role_id)


@router.post("", response_model=RoleResponse, status_code=201)
async def create_role(
    body: RoleCreate,
    db: AsyncSession = Depends(get_db),
    actor: TokenPayload = Depends(require_permission("users:write")),
):
    role = await role_service.create_role(db, body.model_dump())
    await audit_service.log_audit(db, UUID(actor.user_id), "role.create", "role", role["id"])
    return role


@router.put("/{role_id}", response_model=RoleResponse)
async def update_role(
    role_id: UUID,
    body: RoleUpdate,
    db: AsyncSession = Depends(get_db),
    actor: TokenPayload = Depends(require_permission("users:write")),
):
    role = await role_service.update_role(db, role_id, body.model_dump(exclude_unset=True))
    await audit_service.log_audit(db, UUID(actor.user_id), "role.update", "role", role_id)
    return role


@router.delete("/{role_id}", status_code=204)
async def delete_role(
    role_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor: TokenPayload = Depends(require_permission("users:write")),
):
    await role_service.delete_role(db, role_id)
    await audit_service.log_audit(db, UUID(actor.user_id), "role.delete", "role", role_id)
