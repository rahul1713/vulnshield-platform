import json
from uuid import UUID
from urllib.parse import urlparse
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from vulnshield_common.messaging import publish_event

OWASP_TESTS = {
    "sqli": ("A03:2021-Injection", "SQL Injection"),
    "xss": ("A03:2021-Injection", "Cross-Site Scripting"),
    "csrf": ("A01:2021-Broken Access Control", "CSRF"),
    "ssrf": ("A10:2021-SSRF", "Server-Side Request Forgery"),
    "xxe": ("A05:2021-Security Misconfiguration", "XML External Entity"),
    "idor": ("A01:2021-Broken Access Control", "Insecure Direct Object Reference"),
    "auth": ("A07:2021-Identification and Authentication Failures", "Authentication"),
    "misconfig": ("A05:2021-Security Misconfiguration", "Security Misconfiguration"),
    "sensitive": ("A02:2021-Cryptographic Failures", "Sensitive Data Exposure"),
    "components": ("A06:2021-Vulnerable Components", "Vulnerable Components"),
}


async def create_web_scan(db: AsyncSession, data: dict, user_id: UUID | None = None):
    parsed = urlparse(data["target_url"])
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(400, "target_url must be http or https")
    r = await db.execute(
        text("""
            INSERT INTO scans (name, scan_type, status, target_asset_id, target_config, created_by, started_at)
            VALUES (:name, 'web_app', 'running', :asset, CAST(:cfg AS jsonb), :uid, NOW())
            RETURNING id
        """),
        {
            "name": data["name"],
            "asset": str(data["target_asset_id"]) if data.get("target_asset_id") else None,
            "cfg": json.dumps({"target_url": data["target_url"], "crawl_depth": data.get("crawl_depth", 3), "active_tests": data.get("active_tests", [])}),
            "uid": str(user_id) if user_id else None,
        },
    )
    scan_id = r.fetchone().id
    await publish_event("webscan.started", {"scan_id": str(scan_id), "url": data["target_url"]})
    return await get_web_scan(db, scan_id)


async def get_web_scan(db: AsyncSession, scan_id: UUID):
    r = await db.execute(
        text("""
            SELECT id, name, scan_type::text, status::text, target_asset_id, findings_count, created_at
            FROM scans WHERE id = :id AND scan_type = 'web_app'
        """),
        {"id": str(scan_id)},
    )
    row = r.fetchone()
    if not row:
        raise HTTPException(404, "Web scan not found")
    return dict(row._mapping)


async def list_web_scans(db: AsyncSession, limit=50, offset=0):
    r = await db.execute(
        text("""
            SELECT id, name, scan_type::text, status::text, target_asset_id, findings_count, created_at
            FROM scans WHERE scan_type = 'web_app' ORDER BY created_at DESC LIMIT :limit OFFSET :offset
        """),
        {"limit": limit, "offset": offset},
    )
    return [dict(row._mapping) for row in r.fetchall()]


async def crawl_target(db: AsyncSession, scan_id: UUID, base_url: str, depth: int = 3):
    """Simulated crawl producing discovered URL inventory stored in scan_results."""
    pages = [base_url.rstrip("/"), f"{base_url.rstrip('/')}/login", f"{base_url.rstrip('/')}/api"]
    pages = pages[: max(1, depth)]
    await db.execute(
        text("""
            INSERT INTO scan_results (scan_id, raw_data, processed_at)
            VALUES (:sid, CAST(:raw AS jsonb), NOW())
        """),
        {"sid": str(scan_id), "raw": json.dumps({"crawled_urls": pages, "depth": depth})},
    )
    return {"scan_id": str(scan_id), "urls_discovered": len(pages), "urls": pages}


async def run_owasp_tests(db: AsyncSession, scan_id: UUID, tests: list[str]):
    scan = await get_web_scan(db, scan_id)
    cfg_r = await db.execute(text("SELECT target_config FROM scans WHERE id = :id"), {"id": str(scan_id)})
    cfg = cfg_r.fetchone().target_config or {}
    base_url = cfg.get("target_url", "https://example.com")
    findings = 0
    for test_key in tests:
        meta = OWASP_TESTS.get(test_key)
        if not meta:
            continue
        owasp, title = meta
        await db.execute(
            text("""
                INSERT INTO web_scan_findings (scan_id, url, vulnerability_type, owasp_category, severity, title, description, remediation, is_simulated)
                VALUES (:sid, :url, :vtype, :owasp, 'medium', :title, :desc, :rem, TRUE)
            """),
            {
                "sid": str(scan_id),
                "url": base_url,
                "vtype": test_key,
                "owasp": owasp,
                "title": f"Potential {title}",
                "desc": f"Active test '{test_key}' flagged a potential issue during OWASP assessment.",
                "rem": f"Review and remediate {title.lower()} risks.",
            },
        )
        findings += 1
    await db.execute(
        text("UPDATE scans SET findings_count = :fc, status = 'completed', completed_at = NOW() WHERE id = :id"),
        {"id": str(scan_id), "fc": findings},
    )
    await publish_event("webscan.completed", {"scan_id": str(scan_id), "findings": findings})
    return {"scan_id": str(scan_id), "findings_created": findings}


async def list_findings(db: AsyncSession, scan_id: UUID):
    r = await db.execute(
        text("""
            SELECT id, url, parameter, method, vulnerability_type, owasp_category, severity::text,
                   title, description, proof, remediation, cwe_id, is_simulated, created_at
            FROM web_scan_findings WHERE scan_id = :sid ORDER BY created_at DESC
        """),
        {"sid": str(scan_id)},
    )
    return [dict(row._mapping) for row in r.fetchall()]
