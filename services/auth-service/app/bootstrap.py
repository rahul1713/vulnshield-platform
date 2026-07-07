"""Bootstrap initial admin user from environment — never hardcode credentials."""

from __future__ import annotations

import os

import structlog
from sqlalchemy import text

from vulnshield_common.auth import hash_password
from vulnshield_common.config import get_settings
from vulnshield_common.database import AsyncSessionLocal
from vulnshield_common.security import is_protected_environment

logger = structlog.get_logger()
ADMIN_ROLE_ID = "a0000000-0000-0000-0000-000000000001"


async def ensure_bootstrap_admin() -> None:
    """Create the first admin user when INIT_ADMIN_* env vars are set and no users exist."""
    settings = get_settings()
    password = os.getenv("INIT_ADMIN_PASSWORD", "").strip()
    email = os.getenv("INIT_ADMIN_EMAIL", "admin@vulnshield.local").strip()
    username = os.getenv("INIT_ADMIN_USERNAME", "admin").strip()

    if not password:
        if is_protected_environment(settings.environment):
            logger.warning(
                "bootstrap_admin_skipped",
                reason="INIT_ADMIN_PASSWORD not set; no default admin will be created",
            )
        return

    if len(password) < 12:
        raise RuntimeError("INIT_ADMIN_PASSWORD must be at least 12 characters.")

    async with AsyncSessionLocal() as session:
        result = await session.execute(text("SELECT COUNT(*) AS cnt FROM users"))
        count = result.scalar_one()
        if count > 0:
            return

        password_hash = hash_password(password)
        await session.execute(
            text("""
                INSERT INTO users (id, email, username, password_hash, first_name, last_name, role_id, must_change_password)
                VALUES (
                    'b0000000-0000-0000-0000-000000000001',
                    :email, :username, :password_hash,
                    'System', 'Administrator', :role_id, TRUE
                )
            """),
            {
                "email": email,
                "username": username,
                "password_hash": password_hash,
                "role_id": ADMIN_ROLE_ID,
            },
        )
        await session.commit()
        logger.info("bootstrap_admin_created", email=email, username=username)
