from datetime import datetime
from uuid import UUID
from pydantic import BaseModel


class FrameworkResponse(BaseModel):
    id: UUID
    name: str
    version: str | None
    description: str | None
    created_at: datetime


class AssessmentCreate(BaseModel):
    asset_id: UUID | None = None
    framework_id: UUID
    results: list = []


class CISBenchmarkRequest(BaseModel):
    asset_id: UUID
    benchmark_name: str
    platform: str
    results: list = []
