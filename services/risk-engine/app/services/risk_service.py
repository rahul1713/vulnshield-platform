import json
from uuid import UUID
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from vulnshield_common.messaging import publish_event


def _severity_weight(severity: str) -> float:
    return {"critical": 10, "high": 7.5, "medium": 5, "low": 2.5, "info": 1}.get(severity, 3)


async def calculate_vulnerability_risk(db: AsyncSession, vulnerability_id: UUID):
    r = await db.execute(
        text("""
            SELECT v.id, v.severity::text, v.cvss_score, v.epss_score, v.exploit_available,
                   a.criticality, a.business_unit
            FROM vulnerabilities v JOIN assets a ON v.asset_id = a.id
            WHERE v.id = :id
        """),
        {"id": str(vulnerability_id)},
    )
    row = r.fetchone()
    if not row:
        raise HTTPException(404, "Vulnerability not found")
    cvss = float(row.cvss_score or _severity_weight(row.severity))
    epss = float(row.epss_score or 0) * 10
    exploit = 2.0 if row.exploit_available else 0
    technical = min(100, (cvss * 8) + epss + exploit)
    criticality_factor = float(row.criticality or 3) * 5
    business = min(100, technical * 0.6 + criticality_factor * 2)
    overall = round((technical * 0.55 + business * 0.45), 2)
    factors = {
        "cvss": cvss,
        "epss": float(row.epss_score or 0),
        "asset_criticality": row.criticality,
        "exploit_available": row.exploit_available,
        "business_unit": row.business_unit,
    }
    ins = await db.execute(
        text("""
            INSERT INTO risk_scores (entity_type, entity_id, technical_risk, business_risk, likelihood, impact,
                exploitability, exposure, overall_score, factors)
            VALUES ('vulnerability', :eid, :tech, :biz, :like, :impact, :exploit, :exposure, :overall, CAST(:factors AS jsonb))
            RETURNING id, calculated_at
        """),
        {
            "eid": str(vulnerability_id),
            "tech": round(technical, 2),
            "biz": round(business, 2),
            "like": round(epss, 2),
            "impact": round(cvss * 8, 2),
            "exploit": round(exploit * 5, 2),
            "exposure": round(criticality_factor, 2),
            "overall": overall,
            "factors": json.dumps(factors),
        },
    )
    rec = ins.fetchone()
    await db.execute(
        text("UPDATE vulnerabilities SET risk_score = :rs, business_risk_score = :br WHERE id = :id"),
        {"id": str(vulnerability_id), "rs": round(technical, 2), "br": round(business, 2)},
    )
    await publish_event("risk.calculated", {"entity_type": "vulnerability", "entity_id": str(vulnerability_id), "overall": overall})
    return await get_latest_score(db, "vulnerability", vulnerability_id)


async def calculate_asset_risk(db: AsyncSession, asset_id: UUID):
    r = await db.execute(
        text("""
            SELECT a.id, a.criticality, COUNT(v.id) AS vuln_count,
                   COALESCE(MAX(v.cvss_score), 0) AS max_cvss,
                   COALESCE(AVG(v.epss_score), 0) AS avg_epss
            FROM assets a LEFT JOIN vulnerabilities v ON v.asset_id = a.id AND v.status NOT IN ('closed', 'false_positive')
            WHERE a.id = :id GROUP BY a.id, a.criticality
        """),
        {"id": str(asset_id)},
    )
    row = r.fetchone()
    if not row:
        raise HTTPException(404, "Asset not found")
    criticality = float(row.criticality or 3)
    max_cvss = float(row.max_cvss or 0)
    avg_epss = float(row.avg_epss or 0) * 10
    vuln_factor = min(40, float(row.vuln_count or 0) * 2)
    technical = min(100, max_cvss * 7 + avg_epss + vuln_factor)
    business = min(100, technical * 0.5 + criticality * 10)
    overall = round((technical * 0.5 + business * 0.5), 2)
    await db.execute(
        text("""
            INSERT INTO risk_scores (entity_type, entity_id, technical_risk, business_risk, overall_score, factors)
            VALUES ('asset', :eid, :tech, :biz, :overall, CAST(:factors AS jsonb))
        """),
        {
            "eid": str(asset_id),
            "tech": round(technical, 2),
            "biz": round(business, 2),
            "overall": overall,
            "factors": json.dumps({"vuln_count": row.vuln_count, "max_cvss": max_cvss, "criticality": criticality}),
        },
    )
    await publish_event("risk.calculated", {"entity_type": "asset", "entity_id": str(asset_id), "overall": overall})
    return await get_latest_score(db, "asset", asset_id)


async def get_latest_score(db: AsyncSession, entity_type: str, entity_id: UUID):
    r = await db.execute(
        text("""
            SELECT id, entity_type, entity_id, technical_risk, business_risk, likelihood, impact,
                   exploitability, exposure, overall_score, factors, calculated_at
            FROM risk_scores WHERE entity_type = :etype AND entity_id = :eid
            ORDER BY calculated_at DESC LIMIT 1
        """),
        {"etype": entity_type, "eid": str(entity_id)},
    )
    row = r.fetchone()
    if not row:
        raise HTTPException(404, "Risk score not found")
    return dict(row._mapping)


async def list_scores(db: AsyncSession, entity_type: str | None = None, limit=50, offset=0):
    q = """SELECT id, entity_type, entity_id, technical_risk, business_risk, overall_score, calculated_at
           FROM risk_scores WHERE 1=1"""
    params: dict = {"limit": limit, "offset": offset}
    if entity_type:
        q += " AND entity_type = :etype"
        params["etype"] = entity_type
    q += " ORDER BY calculated_at DESC LIMIT :limit OFFSET :offset"
    r = await db.execute(text(q), params)
    return [dict(row._mapping) for row in r.fetchall()]
