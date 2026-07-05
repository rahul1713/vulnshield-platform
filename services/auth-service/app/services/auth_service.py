import hashlib
from datetime import datetime, timezone
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from vulnshield_common.auth import create_access_token, create_refresh_token, decode_token, verify_password
from vulnshield_common.config import get_settings

from app.services import mfa_service

settings = get_settings()
MAX_FAILED = 5
LOCK_MINUTES = 15


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def login(
    db: AsyncSession,
    email: str | None,
    username: str | None,
    password: str,
    mfa_code: str | None,
    ip_address: str | None,
    user_agent: str | None,
) -> dict:
    if not email and not username:
        raise HTTPException(status_code=422, detail="Email or username is required")
    if email:
        lookup = "u.email = :identifier"
    else:
        lookup = "u.username = :identifier"
    result = await db.execute(
        text(f"""
            SELECT u.id, u.email, u.username, u.password_hash, u.is_active, u.is_mfa_enabled,
                   u.must_change_password, u.failed_login_attempts, u.locked_until,
                   u.first_name, u.last_name, u.role_id, u.last_login, u.created_at,
                   r.name AS role_name, r.permissions
            FROM users u JOIN roles r ON u.role_id = r.id WHERE {lookup}
        """),
        {"identifier": email or username},
    )
    user = result.fetchone()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")
    if user.locked_until and user.locked_until > datetime.now(timezone.utc):
        raise HTTPException(status_code=423, detail="Account locked due to failed login attempts")
    if not verify_password(password, user.password_hash):
        attempts = user.failed_login_attempts + 1
        locked = attempts >= MAX_FAILED
        await db.execute(
            text(f"""
                UPDATE users SET failed_login_attempts = :attempts,
                locked_until = CASE WHEN :locked THEN NOW() + INTERVAL '{LOCK_MINUTES} minutes' ELSE locked_until END
                WHERE id = :uid
            """),
            {"attempts": attempts, "locked": locked, "uid": str(user.id)},
        )
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if user.is_mfa_enabled:
        if not mfa_code:
            raise HTTPException(status_code=403, detail="MFA code required")
        if not await mfa_service.verify_mfa_code(db, user.id, mfa_code, enable=False):
            raise HTTPException(status_code=401, detail="Invalid MFA code")
    perms = user.permissions if isinstance(user.permissions, list) else []
    token_data = {"sub": str(user.id), "email": user.email, "role": user.role_name, "permissions": perms}
    access = create_access_token(token_data)
    refresh = create_refresh_token({"sub": str(user.id)})
    await db.execute(
        text(f"""
            INSERT INTO refresh_tokens (user_id, token_hash, expires_at, ip_address, user_agent)
            VALUES (:uid, :hash, NOW() + INTERVAL '{settings.refresh_token_expire_days} days',
                    CAST(:ip AS inet), :ua)
        """),
        {"uid": str(user.id), "hash": _hash_token(refresh), "ip": ip_address, "ua": user_agent},
    )
    await db.execute(
        text("UPDATE users SET last_login = NOW(), failed_login_attempts = 0, locked_until = NULL WHERE id = :uid"),
        {"uid": str(user.id)},
    )
    return {
        "access_token": access,
        "refresh_token": refresh,
        "expires_in": settings.access_token_expire_minutes * 60,
        "must_change_password": user.must_change_password,
        "user": {
            "id": user.id,
            "email": user.email,
            "username": user.username,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "role_id": user.role_id,
            "role_name": user.role_name,
            "is_active": user.is_active,
            "is_mfa_enabled": user.is_mfa_enabled,
            "last_login": user.last_login,
            "created_at": user.created_at,
            "permissions": perms,
        },
    }


async def refresh(db: AsyncSession, refresh_token: str) -> dict:
    payload = decode_token(refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid token type")
    token_hash = _hash_token(refresh_token)
    result = await db.execute(
        text("""
            SELECT rt.id, rt.user_id, u.email, r.name AS role_name, r.permissions
            FROM refresh_tokens rt
            JOIN users u ON rt.user_id = u.id
            JOIN roles r ON u.role_id = r.id
            WHERE rt.token_hash = :hash AND rt.revoked = false AND rt.expires_at > NOW() AND u.is_active = true
        """),
        {"hash": token_hash},
    )
    row = result.fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    await db.execute(text("UPDATE refresh_tokens SET revoked = true WHERE id = :id"), {"id": str(row.id)})
    perms = row.permissions if isinstance(row.permissions, list) else []
    token_data = {"sub": str(row.user_id), "email": row.email, "role": row.role_name, "permissions": perms}
    access = create_access_token(token_data)
    new_refresh = create_refresh_token({"sub": str(row.user_id)})
    await db.execute(
        text(f"""
            INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
            VALUES (:uid, :hash, NOW() + INTERVAL '{settings.refresh_token_expire_days} days')
        """),
        {"uid": str(row.user_id), "hash": _hash_token(new_refresh)},
    )
    return {
        "access_token": access,
        "refresh_token": new_refresh,
        "expires_in": settings.access_token_expire_minutes * 60,
    }


async def logout(db: AsyncSession, refresh_token: str) -> None:
    await db.execute(
        text("UPDATE refresh_tokens SET revoked = true WHERE token_hash = :hash"),
        {"hash": _hash_token(refresh_token)},
    )


async def validate_token(db: AsyncSession, token: str) -> dict:
    payload = decode_token(token)
    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type")
    result = await db.execute(
        text("""
            SELECT u.id, u.email, r.name AS role, r.permissions
            FROM users u JOIN roles r ON u.role_id = r.id
            WHERE u.id = :uid AND u.is_active = true
        """),
        {"uid": payload.get("sub")},
    )
    row = result.fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="User not found")
    return {
        "user_id": str(row.id),
        "email": row.email,
        "role": row.role,
        "permissions": row.permissions if isinstance(row.permissions, list) else [],
    }
