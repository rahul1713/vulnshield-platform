from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, Field

class AssetCreate(BaseModel):
    name: str
    asset_type: str
    status: str = "active"
    ip_address: str | None = None
    hostname: str | None = None
    fqdn: str | None = None
    os_family: str | None = None
    os_version: str | None = None
    criticality: int = Field(default=3, ge=1, le=5)
    business_unit: str | None = None
    owner_id: UUID | None = None
    tags: list[str] = []
    metadata: dict = {}

class AssetUpdate(BaseModel):
    name: str | None = None
    status: str | None = None
    ip_address: str | None = None
    hostname: str | None = None
    criticality: int | None = Field(default=None, ge=1, le=5)
    business_unit: str | None = None
    owner_id: UUID | None = None
    tags: list[str] | None = None
    metadata: dict | None = None

class AssetResponse(BaseModel):
    id: UUID
    name: str
    asset_type: str
    status: str
    ip_address: str | None
    hostname: str | None
    criticality: int
    business_unit: str | None
    tags: list | None
    last_seen: datetime | None
    created_at: datetime

class SoftwareCreate(BaseModel):
    name: str
    version: str | None = None
    vendor: str | None = None
    cpe: str | None = None
    package_manager: str | None = None
    is_running: bool = False

class PortCreate(BaseModel):
    port: int = Field(ge=1, le=65535)
    protocol: str = "tcp"
    service_name: str | None = None
    service_version: str | None = None
    state: str = "open"

class DiscoveryRequest(BaseModel):
    ip_range: str | None = None
    hostname: str | None = None
    asset_type: str = "linux_server"
    tags: list[str] = []

class SearchQuery(BaseModel):
    q: str | None = None
    asset_type: str | None = None
    status: str | None = None
    criticality_min: int | None = None
    criticality_max: int | None = None
    business_unit: str | None = None
    tag: str | None = None
