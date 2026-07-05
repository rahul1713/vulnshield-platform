from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from vulnshield_common.auth import TokenPayload, require_permission
from vulnshield_common.database import get_db

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


class DashboardData(BaseModel):
    total_assets: int
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    open_count: int
    resolved_count: int
    risk_score: float
    compliance_score: float
    patch_coverage: float
    severity_distribution: list[dict]
    risk_trend: list[dict]
    top_vulnerable_assets: list[dict]
    remediation_progress: dict


@router.get("/executive", response_model=DashboardData)
async def executive_dashboard(
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("dashboard:read")),
):
    return await _build_dashboard(db)


@router.get("/soc", response_model=DashboardData)
async def soc_dashboard(
    db: AsyncSession = Depends(get_db),
    _: TokenPayload = Depends(require_permission("dashboard:read")),
):
    return await _build_dashboard(db, soc=True)


async def _build_dashboard(db: AsyncSession, soc: bool = False) -> DashboardData:
    stats = await db.execute(
        text("""
            SELECT
                (SELECT COUNT(*) FROM assets WHERE status = 'active') AS total_assets,
                (SELECT COUNT(*) FROM vulnerabilities) AS total_vulnerabilities,
                (SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'critical' AND status NOT IN ('closed','false_positive','resolved')) AS critical_count,
                (SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'high' AND status NOT IN ('closed','false_positive','resolved')) AS high_count,
                (SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'medium' AND status NOT IN ('closed','false_positive','resolved')) AS medium_count,
                (SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'low' AND status NOT IN ('closed','false_positive','resolved')) AS low_count,
                (SELECT COUNT(*) FROM vulnerabilities WHERE status = 'open') AS open_count,
                (SELECT COUNT(*) FROM vulnerabilities WHERE status IN ('resolved','closed')) AS resolved_count,
                (SELECT COALESCE(AVG(risk_score), 0) FROM vulnerabilities WHERE status NOT IN ('closed','false_positive')) AS risk_score,
                (SELECT COALESCE(AVG(score), 75) FROM compliance_assessments) AS compliance_score,
                (SELECT COALESCE(100.0 * COUNT(*) FILTER (WHERE patch_available) / NULLIF(COUNT(*), 0), 0) FROM vulnerabilities WHERE severity IN ('critical','high')) AS patch_coverage
        """)
    )
    row = stats.fetchone()

    severity_result = await db.execute(
        text("""
            SELECT severity, COUNT(*) AS count FROM vulnerabilities
            WHERE status NOT IN ('closed','false_positive')
            GROUP BY severity ORDER BY count DESC
        """)
    )
    severity_distribution = [
        {"name": r.severity, "value": r.count} for r in severity_result.fetchall()
    ]

    trend_result = await db.execute(
        text("""
            SELECT DATE(first_detected) AS date, COUNT(*) AS count
            FROM vulnerabilities
            WHERE first_detected >= NOW() - INTERVAL '30 days'
            GROUP BY DATE(first_detected) ORDER BY date
        """)
    )
    risk_trend = [{"date": str(r.date), "count": r.count} for r in trend_result.fetchall()]

    top_assets = await db.execute(
        text("""
            SELECT a.id, a.name, a.hostname, COUNT(v.id) AS vuln_count,
                   MAX(v.risk_score) AS max_risk
            FROM assets a JOIN vulnerabilities v ON v.asset_id = a.id
            WHERE v.status NOT IN ('closed','false_positive')
            GROUP BY a.id, a.name, a.hostname
            ORDER BY vuln_count DESC, max_risk DESC NULLS LAST LIMIT 10
        """)
    )
    top_vulnerable_assets = [
        {
            "id": str(r.id),
            "name": r.name,
            "hostname": r.hostname,
            "vulnerability_count": r.vuln_count,
            "max_risk": float(r.max_risk) if r.max_risk else 0,
        }
        for r in top_assets.fetchall()
    ]

    remediation = await db.execute(
        text("""
            SELECT status, COUNT(*) AS count FROM vulnerabilities
            GROUP BY status
        """)
    )
    remediation_progress = {r.status: r.count for r in remediation.fetchall()}

    return DashboardData(
        total_assets=row.total_assets or 0,
        total_vulnerabilities=row.total_vulnerabilities or 0,
        critical_count=row.critical_count or 0,
        high_count=row.high_count or 0,
        medium_count=row.medium_count or 0,
        low_count=row.low_count or 0,
        open_count=row.open_count or 0,
        resolved_count=row.resolved_count or 0,
        risk_score=round(float(row.risk_score or 0), 1),
        compliance_score=round(float(row.compliance_score or 75), 1),
        patch_coverage=round(float(row.patch_coverage or 0), 1),
        severity_distribution=severity_distribution,
        risk_trend=risk_trend,
        top_vulnerable_assets=top_vulnerable_assets,
        remediation_progress=remediation_progress,
    )
