import json
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def list_roles(db: AsyncSession) -> list[dict]:
    result = await db.execute(
        text("SELECT id, name, description, permissions, created_at FROM roles ORDER BY name")
    )
    return [dict(row._mapping) for row in result.fetchall()]


async def get_role(db: AsyncSession, role_id: UUID) -> dict:
    result = await db.execute(
        text("SELECT id, name, description, permissions, created_at FROM roles WHERE id = :rid"),
        {"rid": str(role_id)},
    )
    row = result.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Role not found")
    return dict(row._mapping)


async def create_role(db: AsyncSession, data: dict) -> dict:
    result = await db.execute(
        text("""
            INSERT INTO roles (name, description, permissions)
            VALUES (:name, :desc, CAST(:perms AS jsonb)) RETURNING id
        """),
        {
            "name": data["name"],
            "desc": data.get("description"),
            "perms": json.dumps(data.get("permissions", [])),
        },
    )
    return await get_role(db, result.fetchone().id)


async def update_role(db: AsyncSession, role_id: UUID, data: dict) -> dict:
    fields, params = [], {"rid": str(role_id)}
    if data.get("description") is not None:
        fields.append("description = :desc")
        params["desc"] = data["description"]
    if data.get("permissions") is not None:
        fields.append("permissions = CAST(:perms AS jsonb)")
        params["perms"] = json.dumps(data["permissions"])
    if fields:
        await db.execute(text(f"UPDATE roles SET {', '.join(fields)} WHERE id = :rid"), params)
    return await get_role(db, role_id)


async def delete_role(db: AsyncSession, role_id: UUID) -> None:
    result = await db.execute(
        text("DELETE FROM roles WHERE id = :rid RETURNING id"),
        {"rid": str(role_id)},
    )
    if not result.fetchone():
        raise HTTPException(status_code=404, detail="Role not found")
