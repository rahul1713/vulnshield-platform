import json
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def log_audit(
    db: AsyncSession,
    user_id: UUID | None,
    action: str,
    resource_type: str | None = None,
    resource_id: UUID | None = None,
    details: dict | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> None:
    await db.execute(
        text("""
            INSERT INTO audit_logs (user_id, action, resource_type, resource_id, details, ip_address, user_agent)
            VALUES (:user_id, :action, :resource_type, :resource_id, CAST(:details AS jsonb),
                    CAST(:ip_address AS inet), :user_agent)
        """),
        {
            "user_id": str(user_id) if user_id else None,
            "action": action,
            "resource_type": resource_type,
            "resource_id": str(resource_id) if resource_id else None,
            "details": json.dumps(details or {}),
            "ip_address": ip_address,
            "user_agent": user_agent,
        },
    )


async def list_audit_logs(
    db: AsyncSession,
    limit: int = 50,
    offset: int = 0,
    user_id: UUID | None = None,
    action: str | None = None,
) -> list[dict]:
    query = """
        SELECT id, user_id, action, resource_type, resource_id, details,
               host(ip_address) AS ip_address, created_at
        FROM audit_logs WHERE 1=1
    """
    params: dict = {"limit": limit, "offset": offset}
    if user_id:
        query += " AND user_id = :user_id"
        params["user_id"] = str(user_id)
    if action:
        query += " AND action = :action"
        params["action"] = action
    query += " ORDER BY created_at DESC LIMIT :limit OFFSET :offset"
    result = await db.execute(text(query), params)
    return [dict(row._mapping) for row in result.fetchall()]
