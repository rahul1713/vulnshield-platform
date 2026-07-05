from datetime import datetime
from uuid import UUID
from pydantic import BaseModel


class CampaignCreate(BaseModel):
    name: str
    description: str | None = None
    scope: dict = {}


class CampaignResponse(BaseModel):
    id: UUID
    name: str
    description: str | None
    status: str
    findings_count: int
    created_at: datetime
