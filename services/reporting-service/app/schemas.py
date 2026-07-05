from datetime import datetime
from uuid import UUID
from pydantic import BaseModel


class ReportCreate(BaseModel):
    name: str
    report_type: str
    format: str
    parameters: dict = {}


class ReportResponse(BaseModel):
    id: UUID
    name: str
    report_type: str
    format: str
    status: str
    file_path: str | None
    generated_at: datetime | None
    created_at: datetime
