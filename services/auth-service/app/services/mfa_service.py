import base64
import io

import pyotp
import qrcode
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID


async def setup_mfa(db: AsyncSession, user_id: UUID, email: str) -> dict:
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=email, issuer_name="VulnShield")
    await db.execute(
        text("UPDATE users SET mfa_secret = :secret WHERE id = :uid"),
        {"secret": secret, "uid": str(user_id)},
    )
    qr = qrcode.make(uri)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    return {
        "secret": secret,
        "provisioning_uri": uri,
        "qr_code_base64": base64.b64encode(buf.getvalue()).decode(),
    }


async def verify_mfa_code(db: AsyncSession, user_id: UUID, code: str, enable: bool = True) -> bool:
    result = await db.execute(
        text("SELECT mfa_secret FROM users WHERE id = :uid"),
        {"uid": str(user_id)},
    )
    row = result.fetchone()
    if not row or not row.mfa_secret:
        return False
    if not pyotp.TOTP(row.mfa_secret).verify(code, valid_window=1):
        return False
    if enable:
        await db.execute(
            text("UPDATE users SET is_mfa_enabled = true WHERE id = :uid"),
            {"uid": str(user_id)},
        )
    return True


async def disable_mfa(db: AsyncSession, user_id: UUID) -> None:
    await db.execute(
        text("UPDATE users SET is_mfa_enabled = false, mfa_secret = NULL WHERE id = :uid"),
        {"uid": str(user_id)},
    )


async def get_mfa_status(db: AsyncSession, user_id: UUID) -> dict:
    result = await db.execute(
        text("SELECT is_mfa_enabled, mfa_secret FROM users WHERE id = :uid"),
        {"uid": str(user_id)},
    )
    row = result.fetchone()
    return {"enabled": bool(row.is_mfa_enabled), "verified": bool(row.mfa_secret)}
