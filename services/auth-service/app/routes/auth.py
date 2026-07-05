from uuid import UUID

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from vulnshield_common.auth import TokenPayload, get_current_user, require_permission
from vulnshield_common.database import get_db

from app.schemas import (
    LoginRequest,
    MFASetupResponse,
    MFAStatusResponse,
    MFAVerifyRequest,
    PasswordChange,
    RefreshRequest,
    TokenResponse,
    UserCreate,
    UserResponse,
    UserUpdate,
)
from app.services import audit_service, auth_service, mfa_service, user_service

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    result = await auth_service.login(
        db, body.email, body.username, body.password, body.mfa_code,
        _client_ip(request), request.headers.get("User-Agent"),
    )
    await audit_service.log_audit(
        db, None, "auth.login", "user",
        details={"email": body.email, "username": body.username},
        ip_address=_client_ip(request),
    )
    return TokenResponse(**result)


@router.post("/logout")
async def logout(body: RefreshRequest, db: AsyncSession = Depends(get_db),
                 user: TokenPayload = Depends(get_current_user)):
    await auth_service.logout(db, body.refresh_token)
    await audit_service.log_audit(db, UUID(user.user_id), "auth.logout", "user", UUID(user.user_id))
    return {"message": "Logged out successfully"}


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(body: RefreshRequest, db: AsyncSession = Depends(get_db)):
    result = await auth_service.refresh(db, body.refresh_token)
    return TokenResponse(**result)


@router.get("/me")
async def me(user: TokenPayload = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return await user_service.get_user(db, UUID(user.user_id))


@router.get("/validate")
async def validate(request: Request, db: AsyncSession = Depends(get_db)):
    from fastapi.responses import Response

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return Response(status_code=401)
    try:
        await auth_service.validate_token(db, auth_header[7:])
        return Response(status_code=200)
    except Exception:
        return Response(status_code=401)


@router.post("/password/change")
async def change_password(body: PasswordChange, db: AsyncSession = Depends(get_db),
                          user: TokenPayload = Depends(get_current_user)):
    await user_service.change_password(db, UUID(user.user_id), body.current_password, body.new_password)
    await audit_service.log_audit(db, UUID(user.user_id), "auth.password_change", "user", UUID(user.user_id))
    return {"message": "Password changed successfully"}


@router.post("/mfa/setup", response_model=MFASetupResponse)
async def mfa_setup(user: TokenPayload = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await mfa_service.setup_mfa(db, UUID(user.user_id), user.email)
    return MFASetupResponse(**result)


@router.post("/mfa/verify")
async def mfa_verify(body: MFAVerifyRequest, user: TokenPayload = Depends(get_current_user),
                     db: AsyncSession = Depends(get_db)):
    ok = await mfa_service.verify_mfa_code(db, UUID(user.user_id), body.code)
    if not ok:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="Invalid MFA code")
    await audit_service.log_audit(db, UUID(user.user_id), "auth.mfa_enabled", "user", UUID(user.user_id))
    return {"message": "MFA enabled successfully"}


@router.post("/mfa/disable")
async def mfa_disable(body: MFAVerifyRequest, user: TokenPayload = Depends(get_current_user),
                      db: AsyncSession = Depends(get_db)):
    if not await mfa_service.verify_mfa_code(db, UUID(user.user_id), body.code, enable=False):
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="Invalid MFA code")
    await mfa_service.disable_mfa(db, UUID(user.user_id))
    await audit_service.log_audit(db, UUID(user.user_id), "auth.mfa_disabled", "user", UUID(user.user_id))
    return {"message": "MFA disabled successfully"}


@router.get("/mfa/status", response_model=MFAStatusResponse)
async def mfa_status(user: TokenPayload = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return MFAStatusResponse(**await mfa_service.get_mfa_status(db, UUID(user.user_id)))
