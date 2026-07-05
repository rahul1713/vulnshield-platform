from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, Field


class ScanCreate(BaseModel):
    name: str
    scan_type: str
    target_asset_id: UUID | None = None
    target_config: dict = {}
    schedule_cron: str | None = None


class ScanUpdate(BaseModel):
    name: str | None = None
    status: str | None = None
    error_message: str | None = None


class ScanResponse(BaseModel):
    id: UUID
    name: str
    scan_type: str
    status: str
    target_asset_id: UUID | None
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime


class AgentRegister(BaseModel):
    agent_id: str
    hostname: str | None = None
    platform: str
    version: str | None = None
    asset_id: UUID | None = None
    certificate_fingerprint: str | None = None
    ip_address: str | None = None
    metadata: dict = {}


class AgentHeartbeat(BaseModel):
    agent_id: str
    status: str = "online"
    metadata: dict = {}


class AgentIngestPayload(BaseModel):
    agent_id: str
    scan_data: dict
    certificate_fingerprint: str | None = None


class AgentlessScanRequest(BaseModel):
    name: str
    scan_type: str = Field(pattern="^(agentless_ssh|agentless_winrm|agentless_smb)$")
    target_asset_id: UUID | None = None
    target_config: dict
