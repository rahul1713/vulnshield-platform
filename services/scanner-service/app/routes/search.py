from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from vulnshield_common.auth import TokenPayload, require_permission
from vulnshield_common.database import get_db

router = APIRouter(prefix="/search", tags=["Search"])


class SearchResult(BaseModel):
    type: str
    id: str
    title: str
    subtitle: str | None = None
    severity: str | None = None
    url: str


@router.get("", response_model=list[SearchResult])
async def global_search(
    q: str = Query(..., min_length=1),
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("assets:read")),
):
    pattern = f"%{q}%"
    results: list[SearchResult] = []

    assets = await db.execute(
        text("""
            SELECT id, name, hostname, asset_type::text FROM assets
            WHERE name ILIKE :q OR hostname ILIKE :q OR ip_address::text ILIKE :q
            LIMIT :limit
        """),
        {"q": pattern, "limit": limit // 4 or 1},
    )
    for row in assets.fetchall():
        results.append(SearchResult(
            type="asset",
            id=str(row.id),
            title=row.name,
            subtitle=row.hostname or row.asset_type,
            url=f"/assets/{row.id}",
        ))

    vulns = await db.execute(
        text("""
            SELECT v.id, v.title, v.cve_identifier, v.severity::text, a.name AS asset_name
            FROM vulnerabilities v JOIN assets a ON v.asset_id = a.id
            WHERE v.title ILIKE :q OR v.cve_identifier ILIKE :q OR a.name ILIKE :q
            LIMIT :limit
        """),
        {"q": pattern, "limit": limit // 4 or 1},
    )
    for row in vulns.fetchall():
        results.append(SearchResult(
            type="vulnerability",
            id=str(row.id),
            title=row.title,
            subtitle=row.cve_identifier or row.asset_name,
            severity=row.severity,
            url=f"/vulnerabilities/{row.id}",
        ))

    cves = await db.execute(
        text("""
            SELECT id, cve_id, description, cvss_v3_score FROM cves
            WHERE cve_id ILIKE :q OR description ILIKE :q LIMIT :limit
        """),
        {"q": pattern, "limit": limit // 4 or 1},
    )
    for row in cves.fetchall():
        results.append(SearchResult(
            type="cve",
            id=str(row.id),
            title=row.cve_id,
            subtitle=(row.description or "")[:120],
            severity="critical" if row.cvss_v3_score and row.cvss_v3_score >= 9 else "high" if row.cvss_v3_score and row.cvss_v3_score >= 7 else None,
            url=f"/vulnerabilities?search={row.cve_id}",
        ))

    software = await db.execute(
        text("""
            SELECT s.id, s.name, s.version, a.name AS asset_name
            FROM asset_software s JOIN assets a ON s.asset_id = a.id
            WHERE s.name ILIKE :q OR s.version ILIKE :q LIMIT :limit
        """),
        {"q": pattern, "limit": limit // 4 or 1},
    )
    for row in software.fetchall():
        results.append(SearchResult(
            type="software",
            id=str(row.id),
            title=f"{row.name} {row.version or ''}".strip(),
            subtitle=row.asset_name,
            url="/assets",
        ))

    return results[:limit]
