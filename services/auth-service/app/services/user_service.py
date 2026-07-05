from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from vulnshield_common.auth import hash_password, validate_password_policy, verify_password


async def list_users(db: AsyncSession, limit: int = 50, offset: int = 0) -> list[dict]:
    result = await db.execute(
        text("""
            SELECT u.id, u.email, u.username, u.first_name, u.last_name, u.role_id, r.name AS role_name,
                   u.is_active, u.is_mfa_enabled, u.last_login, u.created_at
            FROM users u JOIN roles r ON u.role_id = r.id
            ORDER BY u.created_at DESC LIMIT :limit OFFSET :offset
        """),
        {"limit": limit, "offset": offset},
    )
    return [dict(row._mapping) for row in result.fetchall()]


async def get_user(db: AsyncSession, user_id: UUID) -> dict:
    result = await db.execute(
        text("""
            SELECT u.id, u.email, u.username, u.first_name, u.last_name, u.role_id, r.name AS role_name,
                   u.is_active, u.is_mfa_enabled, u.last_login, u.created_at
            FROM users u JOIN roles r ON u.role_id = r.id WHERE u.id = :uid
        """),
        {"uid": str(user_id)},
    )
    row = result.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    return dict(row._mapping)


async def create_user(db: AsyncSession, data: dict) -> dict:
    ok, msg = validate_password_policy(data["password"])
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    result = await db.execute(
        text("""
            INSERT INTO users (email, username, password_hash, first_name, last_name, role_id, password_changed_at)
            VALUES (:email, :username, :hash, :fn, :ln, :role_id, NOW()) RETURNING id
        """),
        {
            "email": data["email"],
            "username": data["username"],
            "hash": hash_password(data["password"]),
            "fn": data.get("first_name"),
            "ln": data.get("last_name"),
            "role_id": str(data["role_id"]),
        },
    )
    return await get_user(db, result.fetchone().id)


async def update_user(db: AsyncSession, user_id: UUID, data: dict) -> dict:
    fields, params = [], {"uid": str(user_id)}
    mapping = {
        "email": "email",
        "username": "username",
        "first_name": "first_name",
        "last_name": "last_name",
        "role_id": "role_id",
        "is_active": "is_active",
    }
    for key, column in mapping.items():
        if data.get(key) is not None:
            fields.append(f"{column} = :{key}")
            params[key] = str(data[key]) if key == "role_id" else data[key]
    if fields:
        await db.execute(text(f"UPDATE users SET {', '.join(fields)} WHERE id = :uid"), params)
    return await get_user(db, user_id)


async def delete_user(db: AsyncSession, user_id: UUID) -> None:
    result = await db.execute(
        text("DELETE FROM users WHERE id = :uid RETURNING id"),
        {"uid": str(user_id)},
    )
    if not result.fetchone():
        raise HTTPException(status_code=404, detail="User not found")


async def change_password(db: AsyncSession, user_id: UUID, current: str, new: str) -> None:
    ok, msg = validate_password_policy(new)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    result = await db.execute(
        text("SELECT password_hash FROM users WHERE id = :uid"),
        {"uid": str(user_id)},
    )
    row = result.fetchone()
    if not row or not verify_password(current, row.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    await db.execute(
        text("""
            UPDATE users SET password_hash = :hash, password_changed_at = NOW(), must_change_password = false
            WHERE id = :uid
        """),
        {"hash": hash_password(new), "uid": str(user_id)},
    )
