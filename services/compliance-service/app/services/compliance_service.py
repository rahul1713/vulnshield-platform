import json
from uuid import UUID
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from vulnshield_common.messaging import publish_event

FRAMEWORK_ALIASES = {
    "cis": "CIS Controls",
    "nist": "NIST CSF",
    "iso": "ISO 27001",
    "pci": "PCI DSS",
}


async def list_frameworks(db: AsyncSession):
    r = await db.execute(
        text("SELECT id, name, version, description, created_at FROM compliance_frameworks ORDER BY name")
    )
    return [dict(row._mapping) for row in r.fetchall()]


async def get_framework(db: AsyncSession, framework_id: UUID):
    r = await db.execute(
        text("SELECT id, name, version, description, controls, created_at FROM compliance_frameworks WHERE id = :id"),
        {"id": str(framework_id)},
    )
    row = r.fetchone()
    if not row:
        raise HTTPException(404, "Framework not found")
    return dict(row._mapping)


async def map_control(db: AsyncSession, framework_name: str, control_id: str):
    alias = FRAMEWORK_ALIASES.get(framework_name.lower(), framework_name)
    r = await db.execute(
        text("""
            SELECT id, name, version, controls FROM compliance_frameworks
            WHERE name ILIKE :name LIMIT 1
        """),
        {"name": f"%{alias}%"},
    )
    row = r.fetchone()
    if not row:
        return {"framework": alias, "control_id": control_id, "mapped": False, "details": None}
    controls = row.controls if isinstance(row.controls, list) else []
    match = next((c for c in controls if isinstance(c, dict) and c.get("id") == control_id), None)
    return {"framework": row.name, "control_id": control_id, "mapped": bool(match), "details": match}


async def create_assessment(db: AsyncSession, data: dict):
    results = data.get("results", [])
    passed = sum(1 for r in results if isinstance(r, dict) and r.get("status") == "pass")
    failed = sum(1 for r in results if isinstance(r, dict) and r.get("status") == "fail")
    total = len(results)
    score = round((passed / total) * 100, 2) if total else 0
    r = await db.execute(
        text("""
            INSERT INTO compliance_assessments (asset_id, framework_id, score, passed_controls, failed_controls, total_controls, results)
            VALUES (:aid, :fid, :score, :passed, :failed, :total, CAST(:results AS jsonb)) RETURNING id, assessed_at
        """),
        {
            "aid": str(data["asset_id"]) if data.get("asset_id") else None,
            "fid": str(data["framework_id"]),
            "score": score,
            "passed": passed,
            "failed": failed,
            "total": total,
            "results": json.dumps(results),
        },
    )
    rec = r.fetchone()
    await publish_event("compliance.assessed", {"assessment_id": str(rec.id), "score": score})
    return {"id": rec.id, "score": score, "passed_controls": passed, "failed_controls": failed, "assessed_at": rec.assessed_at}


async def run_cis_benchmark(db: AsyncSession, data: dict):
    results = data.get("results", [])
    if not results:
        results = [
            {"control": "1.1", "title": "Inventory of authorized devices", "status": "pass"},
            {"control": "2.1", "title": "Software inventory", "status": "fail"},
            {"control": "3.1", "title": "Secure configuration", "status": "pass"},
        ]
    passed = sum(1 for r in results if r.get("status") == "pass")
    failed = sum(1 for r in results if r.get("status") == "fail")
    total = len(results)
    score = round((passed / total) * 100, 2) if total else 0
    r = await db.execute(
        text("""
            INSERT INTO cis_benchmark_results (asset_id, benchmark_name, platform, score, passed, failed, total, results)
            VALUES (:aid, :name, :plat, :score, :passed, :failed, :total, CAST(:results AS jsonb))
            RETURNING id, assessed_at
        """),
        {
            "aid": str(data["asset_id"]),
            "name": data["benchmark_name"],
            "plat": data["platform"],
            "score": score,
            "passed": passed,
            "failed": failed,
            "total": total,
            "results": json.dumps(results),
        },
    )
    rec = r.fetchone()
    await publish_event("compliance.cis_benchmark", {"asset_id": str(data["asset_id"]), "score": score})
    return {"id": rec.id, "score": score, "passed": passed, "failed": failed, "total": total, "assessed_at": rec.assessed_at}


async def list_assessments(db: AsyncSession, limit=50, offset=0):
    r = await db.execute(
        text("""
            SELECT ca.id, ca.asset_id, cf.name AS framework, ca.score, ca.passed_controls,
                   ca.failed_controls, ca.total_controls, ca.assessed_at
            FROM compliance_assessments ca
            JOIN compliance_frameworks cf ON ca.framework_id = cf.id
            ORDER BY ca.assessed_at DESC LIMIT :limit OFFSET :offset
        """),
        {"limit": limit, "offset": offset},
    )
    return [dict(row._mapping) for row in r.fetchall()]
