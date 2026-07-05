from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, Field


class WebScanCreate(BaseModel):
    name: str
    target_url: str
    target_asset_id: UUID | None = None
    crawl_depth: int = Field(default=3, ge=1, le=10)
    active_tests: list[str] = Field(default_factory=lambda: ["sqli", "xss", "csrf", "ssrf", "xxe", "idor", "auth", "misconfig", "sensitive", "components"])


class WebFindingCreate(BaseModel):
    url: str
    vulnerability_type: str
    severity: str
    title: str
    description: str | None = None
    owasp_category: str | None = None
    parameter: str | None = None
    method: str | None = "GET"
    proof: str | None = None
    remediation: str | None = None
    cwe_id: str | None = None


class WebScanResponse(BaseModel):
    id: UUID
    name: str
    scan_type: str
    status: str
    target_asset_id: UUID | None
    findings_count: int
    created_at: datetime
