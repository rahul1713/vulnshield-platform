from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from vulnshield_common.auth import TokenPayload, require_permission
from vulnshield_common.database import get_db

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])


class VulnerabilityResponse(BaseModel):
    id: UUID
    asset_id: UUID
    scan_id: UUID | None = None
    cve_identifier: str | None = None
    title: str
    description: str | None = None
    severity: str
    cvss_score: float | None = None
    epss_score: float | None = None
    status: str
    category: str | None = None
    affected_software: str | None = None
    affected_version: str | None = None
    remediation: str | None = None
    exploit_available: bool = False
    patch_available: bool = False
    risk_score: float | None = None
    business_risk_score: float | None = None
    first_detected: str | None = None
    last_detected: str | None = None
    asset_name: str | None = None
    asset_hostname: str | None = None


class PaginatedVulnerabilities(BaseModel):
    items: list[VulnerabilityResponse]
    total: int
    page: int
    page_size: int
    pages: int


def _row_to_vuln(row) -> VulnerabilityResponse:
    return VulnerabilityResponse(
        id=row.id,
        asset_id=row.asset_id,
        scan_id=row.scan_id,
        cve_identifier=row.cve_identifier,
        title=row.title,
        description=row.description,
        severity=row.severity,
        cvss_score=float(row.cvss_score) if row.cvss_score else None,
        epss_score=float(row.epss_score) if row.epss_score else None,
        status=row.status,
        category=row.category,
        affected_software=row.affected_software,
        affected_version=row.affected_version,
        remediation=row.remediation,
        exploit_available=row.exploit_available,
        patch_available=row.patch_available,
        risk_score=float(row.risk_score) if row.risk_score else None,
        business_risk_score=float(row.business_risk_score) if row.business_risk_score else None,
        first_detected=row.first_detected.isoformat() if row.first_detected else None,
        last_detected=row.last_detected.isoformat() if row.last_detected else None,
        asset_name=row.asset_name,
        asset_hostname=row.asset_hostname,
    )


@router.get("", response_model=PaginatedVulnerabilities)
async def list_vulnerabilities(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    severity: str | None = None,
    status: str | None = None,
    asset_id: UUID | None = None,
    search: str | None = None,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("vulnerabilities:read")),
):
    offset = (page - 1) * page_size
    conditions = ["1=1"]
    params: dict = {"limit": page_size, "offset": offset}

    if severity:
        conditions.append("v.severity = :severity")
        params["severity"] = severity
    if status:
        conditions.append("v.status = :status")
        params["status"] = status
    if asset_id:
        conditions.append("v.asset_id = :asset_id")
        params["asset_id"] = str(asset_id)
    if search:
        conditions.append(
            "(v.title ILIKE :search OR v.cve_identifier ILIKE :search OR a.name ILIKE :search)"
        )
        params["search"] = f"%{search}%"

    where = " AND ".join(conditions)
    count_result = await db.execute(
        text(f"""
            SELECT COUNT(*) FROM vulnerabilities v
            JOIN assets a ON v.asset_id = a.id WHERE {where}
        """),
        params,
    )
    total = count_result.scalar() or 0

    result = await db.execute(
        text(f"""
            SELECT v.*, a.name AS asset_name, a.hostname AS asset_hostname
            FROM vulnerabilities v
            JOIN assets a ON v.asset_id = a.id
            WHERE {where}
            ORDER BY v.risk_score DESC NULLS LAST, v.cvss_score DESC NULLS LAST
            LIMIT :limit OFFSET :offset
        """),
        params,
    )
    items = [_row_to_vuln(row) for row in result.fetchall()]
    pages = max(1, (total + page_size - 1) // page_size)
    return PaginatedVulnerabilities(items=items, total=total, page=page, page_size=page_size, pages=pages)


@router.get("/{vulnerability_id}", response_model=VulnerabilityResponse)
async def get_vulnerability(
    vulnerability_id: UUID,
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("vulnerabilities:read")),
):
    result = await db.execute(
        text("""
            SELECT v.*, a.name AS asset_name, a.hostname AS asset_hostname
            FROM vulnerabilities v JOIN assets a ON v.asset_id = a.id WHERE v.id = :id
        """),
        {"id": str(vulnerability_id)},
    )
    row = result.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return _row_to_vuln(row)


@router.patch("/{vulnerability_id}/status")
async def update_status(
    vulnerability_id: UUID,
    status: str,
    comment: str | None = None,
    db: AsyncSession = Depends(get_db),
    user: TokenPayload = Depends(require_permission("vulnerabilities:write")),
):
    result = await db.execute(
        text("SELECT status FROM vulnerabilities WHERE id = :id"),
        {"id": str(vulnerability_id)},
    )
    row = result.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    await db.execute(
        text("UPDATE vulnerabilities SET status = :status, updated_at = NOW() WHERE id = :id"),
        {"id": str(vulnerability_id), "status": status},
    )
    await db.execute(
        text("""
            INSERT INTO vulnerability_history (vulnerability_id, old_status, new_status, changed_by, comment)
            VALUES (:vid, :old, :new, :uid, :comment)
        """),
        {
            "vid": str(vulnerability_id),
            "old": row.status,
            "new": status,
            "uid": user.user_id,
            "comment": comment,
        },
    )
    return {"message": "Status updated", "status": status}
