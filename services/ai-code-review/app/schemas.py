from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, Field


class CodeReviewCreate(BaseModel):
    repository_url: str | None = None
    branch: str = "main"
    language: str
    source_code: str | None = None
    file_path: str | None = None


class CodeReviewResponse(BaseModel):
    id: UUID
    repository_url: str | None
    branch: str
    language: str
    status: str
    findings_count: int
    created_at: datetime
