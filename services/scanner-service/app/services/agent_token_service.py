"""Machine token verification for endpoint agents."""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from vulnshield_common.auth import TokenPayload, require_permission
from vulnshield_common.database import get_db


class AgentTokenPayload:
    def __init__(self, agent_id: str, token_id: str, scopes: list[str]):
        self.agent_id = agent_id
        self.token_id = token_id
        self.scopes = scopes


def hash_agent_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def generate_agent_token() -> str:
    return f"vsat_{secrets.token_urlsafe(32)}"


async def create_agent_token(
    db: AsyncSession,
    *,
    agent_id: str,
    created_by: str | None,
    label: str | None = None,
    scopes: list[str] | None = None,
    expires_days: int = 365,
) -> dict[str, Any]:
    raw = generate_agent_token()
    token_hash = hash_agent_token(raw)
    scope_list = scopes or ["agent:register", "agent:heartbeat", "agent:ingest"]
    expires_at = datetime.now(timezone.utc) + timedelta(days=expires_days)

    r = await db.execute(
        text("""
            INSERT INTO agent_tokens (agent_id, token_hash, label, scopes, expires_at, created_by)
            VALUES (:aid, :hash, :label, CAST(:scopes AS jsonb), :exp, :uid)
            RETURNING id, agent_id, label, scopes, expires_at, created_at
        """),
        {
            "aid": agent_id,
            "hash": token_hash,
            "label": label,
            "scopes": __import__("json").dumps(scope_list),
            "exp": expires_at,
            "uid": created_by,
        },
    )
    row = r.fetchone()
    return {
        "id": str(row.id),
        "agent_id": row.agent_id,
        "label": row.label,
        "scopes": row.scopes if isinstance(row.scopes, list) else scope_list,
        "expires_at": row.expires_at.isoformat() if row.expires_at else None,
        "token": raw,
    }


async def verify_agent_token(db: AsyncSession, token: str, required_scope: str) -> AgentTokenPayload:
    token_hash = hash_agent_token(token)
    r = await db.execute(
        text("""
            SELECT id, agent_id, scopes, expires_at, is_active, revoked_at
            FROM agent_tokens WHERE token_hash = :hash
        """),
        {"hash": token_hash},
    )
    row = r.fetchone()
    if not row:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid agent token")
    if not row.is_active or row.revoked_at:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Agent token revoked")
    if row.expires_at and row.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Agent token expired")

    scopes = row.scopes if isinstance(row.scopes, list) else []
    if required_scope not in scopes and "*" not in scopes:
        raise HTTPException(status.HTTP_403_FORBIDDEN, f"Agent token missing scope: {required_scope}")

    await db.execute(
        text("UPDATE agent_tokens SET last_used_at = NOW() WHERE id = :id"),
        {"id": str(row.id)},
    )
    return AgentTokenPayload(agent_id=row.agent_id, token_id=str(row.id), scopes=scopes)


def require_agent_scope(scope: str):
    async def checker(
        x_agent_token: str | None = Header(None, alias="X-Agent-Token"),
        authorization: str | None = Header(None),
        db: AsyncSession = Depends(get_db),
    ) -> AgentTokenPayload:
        token = x_agent_token
        if not token and authorization and authorization.lower().startswith("bearer "):
            token = authorization[7:].strip()
        if not token:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Agent token required")
        return await verify_agent_token(db, token, scope)

    return checker


async def issue_token_for_agent(
    db: AsyncSession,
    agent_id: str,
    user: TokenPayload,
    label: str | None = None,
) -> dict[str, Any]:
    return await create_agent_token(
        db,
        agent_id=agent_id,
        created_by=user.user_id,
        label=label or f"agent-token-{agent_id[:8]}",
    )
