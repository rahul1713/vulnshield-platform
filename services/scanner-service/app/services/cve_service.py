import json
from uuid import UUID
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from vulnshield_common.messaging import publish_event


async def correlate_scan(db: AsyncSession, scan_id: UUID):
    scan_r = await db.execute(text("SELECT id, target_asset_id FROM scans WHERE id = :id"), {"id": str(scan_id)})
    scan = scan_r.fetchone()
    if not scan:
        raise HTTPException(404, "Scan not found")
    if not scan.target_asset_id:
        raise HTTPException(400, "Scan has no target asset for CVE correlation")

    sw_r = await db.execute(
        text("SELECT name, version, cpe FROM asset_software WHERE asset_id = :aid"),
        {"aid": str(scan.target_asset_id)},
    )
    software = sw_r.fetchall()
    matched = 0
    for sw in software:
        cpe = sw.cpe or f"cpe:2.3:a:*:{sw.name.lower()}:{sw.version or '*'}:*:*:*:*:*:*:*"
        cve_r = await db.execute(
            text("""
                SELECT id, cve_id, description, cvss_v3_score, epss_score, is_kev
                FROM cves WHERE cpes @> CAST(:cpe AS jsonb) OR cpes::text ILIKE :like
                ORDER BY cvss_v3_score DESC NULLS LAST LIMIT 50
            """),
            {"cpe": json.dumps([cpe]), "like": f"%{sw.name}%"},
        )
        for cve in cve_r.fetchall():
            await db.execute(
                text("""
                    INSERT INTO vulnerabilities (asset_id, scan_id, cve_id, cve_identifier, title, description,
                        severity, cvss_score, epss_score, affected_software, affected_version, exploit_available, patch_available)
                    SELECT :aid, :sid, :cid, :cve_id, :title, :desc,
                        CASE WHEN :cvss >= 9 THEN 'critical'::severity WHEN :cvss >= 7 THEN 'high'::severity
                             WHEN :cvss >= 4 THEN 'medium'::severity WHEN :cvss >= 0.1 THEN 'low'::severity
                             ELSE 'info'::severity END,
                        :cvss, :epss, :sw, :ver, :kev, FALSE
                    WHERE NOT EXISTS (
                        SELECT 1 FROM vulnerabilities v
                        WHERE v.asset_id = :aid AND v.cve_identifier = :cve_id AND v.status NOT IN ('closed', 'false_positive')
                    )
                """),
                {
                    "aid": str(scan.target_asset_id),
                    "sid": str(scan_id),
                    "cid": str(cve.id),
                    "cve_id": cve.cve_id,
                    "title": f"{cve.cve_id} - {sw.name}",
                    "desc": cve.description,
                    "cvss": float(cve.cvss_v3_score or 0),
                    "epss": float(cve.epss_score or 0),
                    "sw": sw.name,
                    "ver": sw.version,
                    "kev": cve.is_kev,
                },
            )
            matched += 1

    await publish_event("scan.cve_correlated", {"scan_id": str(scan_id), "matched": matched})
    return {"scan_id": str(scan_id), "correlated_vulnerabilities": matched}
