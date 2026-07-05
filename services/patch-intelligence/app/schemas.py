from datetime import date, datetime
from uuid import UUID
from pydantic import BaseModel


class PatchCreate(BaseModel):
    vulnerability_id: UUID | None = None
    cve_id: UUID | None = None
    patch_available: bool = False
    patch_id: str | None = None
    patch_title: str | None = None
    patch_severity: str | None = None
    patch_release_date: date | None = None
    patch_download_url: str | None = None
    vendor_advisory_url: str | None = None
    workaround: str | None = None
    eol_status: bool = False
    eol_date: date | None = None


class PatchResponse(BaseModel):
    id: UUID
    vulnerability_id: UUID | None
    cve_id: UUID | None
    patch_available: bool
    patch_title: str | None
    vendor_advisory_url: str | None
    eol_status: bool
    eol_date: date | None
    created_at: datetime
