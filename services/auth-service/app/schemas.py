from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field


class UserResponse(BaseModel):
    id: UUID
    email: str
    username: str
    first_name: str | None
    last_name: str | None
    role_id: UUID
    role_name: str | None = None
    permissions: list[str] = []
    is_active: bool
    is_mfa_enabled: bool
    last_login: datetime | None
    created_at: datetime


class LoginRequest(BaseModel):
    email: EmailStr | None = None
    username: str | None = None
    password: str
    mfa_code: str | None = None


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    must_change_password: bool = False
    user: UserResponse | None = None


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
    verified: bool
