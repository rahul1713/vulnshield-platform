#!/usr/bin/env python3
"""Build all VulnShield microservice files."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
S = ROOT / "services"
created: list[str] = []

def w(rel: str, content: str):
    p = ROOT / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content.rstrip() + "\n")
    created.append(rel)

def df(svc: str, port: int):
    w(f"services/{svc}/Dockerfile", f"""FROM python:3.11-slim
WORKDIR /app
COPY shared/python /shared/python
RUN pip install --no-cache-dir /shared/python
COPY services/{svc}/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY services/{svc}/app /app/app
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "{port}"]""")

def main_py(title, desc, routes, port):
    ri = "\n".join(f"from app.routes import {r}" for r in routes)
    inc = "\n".join(f'app.include_router({r}.router, prefix="/api/v1")' for r in routes)
    w(f"services/{title.lower().replace(' ','-').replace('api-gateway','api-gateway')}/app/main.py", f'''"""{title}."""
from contextlib import asynccontextmanager
import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import make_asgi_app
from vulnshield_common.config import get_settings
{ri}
logger = structlog.get_logger()
settings = get_settings()

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("service_starting", service="{title}")
    yield
    logger.info("service_stopping", service="{title}")

app = FastAPI(title="{title}", description="{desc}", version="1.0.0", lifespan=lifespan,
    docs_url="/docs", redoc_url="/redoc", openapi_url="/openapi.json")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"])
{inc}
app.mount("/metrics", make_asgi_app())

@app.get("/health", tags=["Health"])
async def health():
    return {{"status": "healthy", "service": "{title}", "port": {port}}}

@app.get("/", tags=["Health"])
async def root():
    return {{"service": "{title}", "docs": "/docs"}}''')

def tests(svc, name):
    w(f"services/{svc}/tests/conftest.py", '''import pytest
from httpx import ASGITransport, AsyncClient
from app.main import app

@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c''')
    w(f"services/{svc}/tests/test_health.py", f'''import pytest

@pytest.mark.asyncio
async def test_health(client):
    r = await client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "healthy"
    assert r.json()["service"] == "{name}"''')

# ============ AUTH SERVICE ============
df("auth-service", 8001)
w("services/auth-service/requirements.txt", """vulnshield-common
pyotp>=2.9.0
qrcode>=7.4.2
redis>=5.0.1
pytest>=8.0.0
pytest-asyncio>=0.23.0
httpx>=0.26.0""")

w("services/auth-service/app/schemas.py", '''from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, EmailStr, Field

class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    mfa_code: str | None = None

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    must_change_password: bool = False

class RefreshRequest(BaseModel):
    refresh_token: str

class UserCreate(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=100)
    password: str
    first_name: str | None = None
    last_name: str | None = None
    role_id: UUID

class UserUpdate(BaseModel):
    email: EmailStr | None = None
    username: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    role_id: UUID | None = None
    is_active: bool | None = None

class PasswordChange(BaseModel):
    current_password: str
    new_password: str

class UserResponse(BaseModel):
    id: UUID
    email: str
    username: str
    first_name: str | None
    last_name: str | None
    role_id: UUID
    role_name: str | None = None
    is_active: bool
    is_mfa_enabled: bool
    last_login: datetime | None
    created_at: datetime

class RoleCreate(BaseModel):
    name: str = Field(min_length=2, max_length=50)
    description: str | None = None
    permissions: list[str] = []

class RoleUpdate(BaseModel):
    description: str | None = None
    permissions: list[str] | None = None

class RoleResponse(BaseModel):
    id: UUID
    name: str
    description: str | None
    permissions: list[str]
    created_at: datetime

class AuditLogResponse(BaseModel):
    id: UUID
    user_id: UUID | None
    action: str
    resource_type: str | None
    resource_id: UUID | None
    details: dict | None
    ip_address: str | None
    created_at: datetime

class MFASetupResponse(BaseModel):
    secret: str
    provisioning_uri: str
    qr_code_base64: str | None = None

class MFAVerifyRequest(BaseModel):
    code: str

class MFAStatusResponse(BaseModel):
    enabled: bool
    verified: bool''')

w("services/auth-service/app/services/audit_service.py", '''from uuid import UUID
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

async def log_audit(db: AsyncSession, user_id: UUID | None, action: str,
    resource_type: str | None = None, resource_id: UUID | None = None,
    details: dict | None = None, ip_address: str | None = None, user_agent: str | None = None):
    await db.execute(text("""
        INSERT INTO audit_logs (user_id, action, resource_type, resource_id, details, ip_address, user_agent)
        VALUES (:user_id, :action, :resource_type, :resource_id, :details::jsonb, :ip_address::inet, :user_agent)
    """), {"user_id": str(user_id) if user_id else None, "action": action,
        "resource_type": resource_type, "resource_id": str(resource_id) if resource_id else None,
        "details": __import__("json").dumps(details or {}), "ip_address": ip_address, "user_agent": user_agent})

async def list_audit_logs(db: AsyncSession, limit: int = 50, offset: int = 0,
    user_id: UUID | None = None, action: str | None = None):
    q = "SELECT id, user_id, action, resource_type, resource_id, details, ip_address::text, created_at FROM audit_logs WHERE 1=1"
    params: dict = {"limit": limit, "offset": offset}
    if user_id:
        q += " AND user_id = :user_id"; params["user_id"] = str(user_id)
    if action:
        q += " AND action = :action"; params["action"] = action
    q += " ORDER BY created_at DESC LIMIT :limit OFFSET :offset"
    r = await db.execute(text(q), params)
    return [dict(row._mapping) for row in r.fetchall()]''')

w("services/auth-service/app/services/mfa_service.py", '''import base64
import io
import pyotp
import qrcode
from uuid import UUID
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

async def setup_mfa(db: AsyncSession, user_id: UUID, email: str) -> dict:
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=email, issuer_name="VulnShield")
    await db.execute(text("UPDATE users SET mfa_secret = :secret WHERE id = :uid"),
        {"secret": secret, "uid": str(user_id)})
    qr = qrcode.make(uri)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    return {"secret": secret, "provisioning_uri": uri,
        "qr_code_base64": base64.b64encode(buf.getvalue()).decode()}

async def verify_mfa_code(db: AsyncSession, user_id: UUID, code: str) -> bool:
    r = await db.execute(text("SELECT mfa_secret FROM users WHERE id = :uid"), {"uid": str(user_id)})
    row = r.fetchone()
    if not row or not row.mfa_secret:
        return False
    if pyotp.TOTP(row.mfa_secret).verify(code, valid_window=1):
        await db.execute(text("UPDATE users SET is_mfa_enabled = true WHERE id = :uid"), {"uid": str(user_id)})
        return True
    return False

async def disable_mfa(db: AsyncSession, user_id: UUID):
    await db.execute(text("UPDATE users SET is_mfa_enabled = false, mfa_secret = NULL WHERE id = :uid"),
        {"uid": str(user_id)})

async def get_mfa_status(db: AsyncSession, user_id: UUID) -> dict:
    r = await db.execute(text("SELECT is_mfa_enabled, mfa_secret FROM users WHERE id = :uid"),
        {"uid": str(user_id)})
    row = r.fetchone()
    return {"enabled": bool(row.is_mfa_enabled), "verified": bool(row.mfa_secret)}''')

w("services/auth-service/app/services/user_service.py", '''from uuid import UUID
from fastapi import HTTPException, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from vulnshield_common.auth import hash_password, validate_password_policy

async def list_users(db: AsyncSession, limit: int = 50, offset: int = 0):
    r = await db.execute(text("""
        SELECT u.id, u.email, u.username, u.first_name, u.last_name, u.role_id, r.name as role_name,
               u.is_active, u.is_mfa_enabled, u.last_login, u.created_at
        FROM users u JOIN roles r ON u.role_id = r.id
        ORDER BY u.created_at DESC LIMIT :limit OFFSET :offset
    """), {"limit": limit, "offset": offset})
    return [dict(row._mapping) for row in r.fetchall()]

async def get_user(db: AsyncSession, user_id: UUID):
    r = await db.execute(text("""
        SELECT u.id, u.email, u.username, u.first_name, u.last_name, u.role_id, r.name as role_name,
               u.is_active, u.is_mfa_enabled, u.last_login, u.created_at
        FROM users u JOIN roles r ON u.role_id = r.id WHERE u.id = :uid
    """), {"uid": str(user_id)})
    row = r.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    return dict(row._mapping)

async def create_user(db: AsyncSession, data: dict):
    ok, msg = validate_password_policy(data["password"])
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    r = await db.execute(text("""
        INSERT INTO users (email, username, password_hash, first_name, last_name, role_id, password_changed_at)
        VALUES (:email, :username, :hash, :fn, :ln, :role_id, NOW()) RETURNING id
    """), {"email": data["email"], "username": data["username"],
        "hash": hash_password(data["password"]), "fn": data.get("first_name"),
        "ln": data.get("last_name"), "role_id": str(data["role_id"])})
    uid = r.fetchone().id
    return await get_user(db, uid)

async def update_user(db: AsyncSession, user_id: UUID, data: dict):
    fields, params = [], {"uid": str(user_id)}
    for k, col in [("email","email"),("username","username"),("first_name","first_name"),
                   ("last_name","last_name"),("role_id","role_id"),("is_active","is_active")]:
        if data.get(k) is not None:
            fields.append(f"{col} = :{k}")
            params[k] = str(data[k]) if k == "role_id" else data[k]
    if fields:
        await db.execute(text(f"UPDATE users SET {', '.join(fields)} WHERE id = :uid"), params)
    return await get_user(db, user_id)

async def delete_user(db: AsyncSession, user_id: UUID):
    r = await db.execute(text("DELETE FROM users WHERE id = :uid RETURNING id"), {"uid": str(user_id)})
    if not r.fetchone():
        raise HTTPException(status_code=404, detail="User not found")

async def change_password(db: AsyncSession, user_id: UUID, current: str, new: str):
    from vulnshield_common.auth import verify_password
    ok, msg = validate_password_policy(new)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    r = await db.execute(text("SELECT password_hash FROM users WHERE id = :uid"), {"uid": str(user_id)})
    row = r.fetchone()
    if not row or not verify_password(current, row.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    await db.execute(text("""
        UPDATE users SET password_hash = :hash, password_changed_at = NOW(), must_change_password = false
        WHERE id = :uid
    """), {"hash": hash_password(new), "uid": str(user_id)})''')

w("services/auth-service/app/services/role_service.py", '''from uuid import UUID
import json
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

async def list_roles(db: AsyncSession):
    r = await db.execute(text("SELECT id, name, description, permissions, created_at FROM roles ORDER BY name"))
    return [dict(row._mapping) for row in r.fetchall()]

async def get_role(db: AsyncSession, role_id: UUID):
    r = await db.execute(text("SELECT id, name, description, permissions, created_at FROM roles WHERE id = :rid"),
        {"rid": str(role_id)})
    row = r.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Role not found")
    return dict(row._mapping)

async def create_role(db: AsyncSession, data: dict):
    r = await db.execute(text("""
        INSERT INTO roles (name, description, permissions) VALUES (:name, :desc, :perms::jsonb) RETURNING id
    """), {"name": data["name"], "desc": data.get("description"),
        "perms": json.dumps(data.get("permissions", []))})
    return await get_role(db, r.fetchone().id)

async def update_role(db: AsyncSession, role_id: UUID, data: dict):
    fields, params = [], {"rid": str(role_id)}
    if data.get("description") is not None:
        fields.append("description = :desc"); params["desc"] = data["description"]
    if data.get("permissions") is not None:
        fields.append("permissions = :perms::jsonb"); params["perms"] = json.dumps(data["permissions"])
    if fields:
        await db.execute(text(f"UPDATE roles SET {', '.join(fields)} WHERE id = :rid"), params)
    return await get_role(db, role_id)

async def delete_role(db: AsyncSession, role_id: UUID):
    r = await db.execute(text("DELETE FROM roles WHERE id = :rid RETURNING id"), {"rid": str(role_id)})
    if not r.fetchone():
        raise HTTPException(status_code=404, detail="Role not found")''')

w("services/auth-service/app/services/auth_service.py", '''import hashlib
from datetime import datetime, timezone
from uuid import UUID
from fastapi import HTTPException, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from vulnshield_common.auth import (
    create_access_token, create_refresh_token, decode_token, verify_password, hash_password,
)
from vulnshield_common.config import get_settings
from app.services import mfa_service

settings = get_settings()
MAX_FAILED = 5
LOCK_MINUTES = 15

def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

async def login(db: AsyncSession, email: str, password: str, mfa_code: str | None,
    ip_address: str | None, user_agent: str | None) -> dict:
    r = await db.execute(text("""
        SELECT u.id, u.email, u.password_hash, u.is_active, u.is_mfa_enabled, u.must_change_password,
               u.failed_login_attempts, u.locked_until, r.name as role_name, r.permissions
        FROM users u JOIN roles r ON u.role_id = r.id WHERE u.email = :email
    """), {"email": email})
    user = r.fetchone()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")
    if user.locked_until and user.locked_until > datetime.now(timezone.utc):
        raise HTTPException(status_code=423, detail="Account locked due to failed login attempts")
    if not verify_password(password, user.password_hash):
        attempts = user.failed_login_attempts + 1
        locked = attempts >= MAX_FAILED
        await db.execute(text("""
            UPDATE users SET failed_login_attempts = :a,
            locked_until = CASE WHEN :locked THEN NOW() + INTERVAL ':mins minutes' ELSE locked_until END
            WHERE id = :uid
        """.replace(":mins", str(LOCK_MINUTES))), {"a": attempts, "locked": locked, "uid": str(user.id)})
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if user.is_mfa_enabled:
        if not mfa_code:
            raise HTTPException(status_code=403, detail="MFA code required")
        if not await mfa_service.verify_mfa_code(db, user.id, mfa_code):
            raise HTTPException(status_code=401, detail="Invalid MFA code")
    perms = user.permissions if isinstance(user.permissions, list) else []
    token_data = {"sub": str(user.id), "email": user.email, "role": user.role_name, "permissions": perms}
    access = create_access_token(token_data)
    refresh = create_refresh_token({"sub": str(user.id)})
    await db.execute(text("""
        INSERT INTO refresh_tokens (user_id, token_hash, expires_at, ip_address, user_agent)
        VALUES (:uid, :hash, NOW() + INTERVAL ':days days', :ip::inet, :ua)
    """.replace(":days", str(settings.refresh_token_expire_days))),
        {"uid": str(user.id), "hash": _hash_token(refresh), "ip": ip_address, "ua": user_agent})
    await db.execute(text("""
        UPDATE users SET last_login = NOW(), failed_login_attempts = 0, locked_until = NULL WHERE id = :uid
    """), {"uid": str(user.id)})
    return {"access_token": access, "refresh_token": refresh,
        "expires_in": settings.access_token_expire_minutes * 60,
        "must_change_password": user.must_change_password}

async def refresh(db: AsyncSession, refresh_token: str) -> dict:
    payload = decode_token(refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid token type")
    th = _hash_token(refresh_token)
    r = await db.execute(text("""
        SELECT rt.id, rt.user_id, u.email, r.name as role_name, r.permissions
        FROM refresh_tokens rt JOIN users u ON rt.user_id = u.id JOIN roles r ON u.role_id = r.id
        WHERE rt.token_hash = :hash AND rt.revoked = false AND rt.expires_at > NOW() AND u.is_active = true
    """), {"hash": th})
    row = r.fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    await db.execute(text("UPDATE refresh_tokens SET revoked = true WHERE id = :id"), {"id": str(row.id)})
    perms = row.permissions if isinstance(row.permissions, list) else []
    token_data = {"sub": str(row.user_id), "email": row.email, "role": row.role_name, "permissions": perms}
    access = create_access_token(token_data)
    new_refresh = create_refresh_token({"sub": str(row.user_id)})
    await db.execute(text("""
        INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (:uid, :hash, NOW() + INTERVAL ':days days')
    """.replace(":days", str(settings.refresh_token_expire_days))),
        {"uid": str(row.user_id), "hash": _hash_token(new_refresh)})
    return {"access_token": access, "refresh_token": new_refresh,
        "expires_in": settings.access_token_expire_minutes * 60}

async def logout(db: AsyncSession, refresh_token: str):
    th = _hash_token(refresh_token)
    await db.execute(text("UPDATE refresh_tokens SET revoked = true WHERE token_hash = :hash"), {"hash": th})

async def validate_token(db: AsyncSession, token: str) -> dict:
    payload = decode_token(token)
    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type")
    r = await db.execute(text("""
        SELECT u.id, u.email, r.name as role, r.permissions FROM users u
        JOIN roles r ON u.role_id = r.id WHERE u.id = :uid AND u.is_active = true
    """), {"uid": payload.get("sub")})
    row = r.fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="User not found")
    return {"user_id": str(row.id), "email": row.email, "role": row.role,
        "permissions": row.permissions if isinstance(row.permissions, list) else []}''')

print("Part 1 done - run part 2")
