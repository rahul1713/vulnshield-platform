import json
from uuid import UUID
from urllib.parse import urlparse

from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from vulnshield_common.messaging import publish_event
from vulnshield_common.scan_sandbox import (
    allow_simulated_scans,
    is_scan_sandbox_mode,
    validate_scan_config_or_raise,
    validate_target_or_raise,
)
from vulnshield_common.scan_engines import (
    EngineUnavailableError,
    OWASP_NUCLEI_TAGS,
    crawl_urls,
    engines_status,
    httpx_probe,
    nuclei_to_web_finding,
    run_nuclei,
)

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


def _allow_simulated() -> bool:
    return allow_simulated_scans()


def _use_real_engines() -> bool:
    return is_scan_sandbox_mode()


def _engine_unavailable_detail(exc: Exception) -> str:
    status = engines_status()
    return (
        f"{exc}. Engine status: {status}. "
        "Install nuclei/enable SCAN_SANDBOX_MODE or set ALLOW_SIMULATED_SCANS=true for dev fallback."
    )

async def create_web_scan(db: AsyncSession, data: dict, user_id: UUID | None = None):
    parsed = urlparse(data["target_url"])
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(400, "target_url must be http or https")
    validate_target_or_raise(data["target_url"], field="target_url")
    validate_scan_config_or_raise({"target_url": data["target_url"]})
    r = await db.execute(
        text("""
            INSERT INTO scans (name, scan_type, status, target_asset_id, target_config, created_by, started_at)
            VALUES (:name, 'web_app', 'running', :asset, CAST(:cfg AS jsonb), :uid, NOW())
            RETURNING id
        """),
        {
            "name": data["name"],
            "asset": str(data["target_asset_id"]) if data.get("target_asset_id") else None,
            "cfg": json.dumps({
                "target_url": data["target_url"],
                "crawl_depth": data.get("crawl_depth", 3),
                "active_tests": data.get("active_tests", []),
            }),
            "uid": str(user_id) if user_id else None,
        },
    )
    scan_id = r.fetchone().id
    await publish_event("webscan.started", {"scan_id": str(scan_id), "url": data["target_url"]})
    return await get_web_scan(db, scan_id)


async def execute_web_scan(db: AsyncSession, scan_id: UUID):
    """Run crawl + OWASP tests inline (scan-worker can call this endpoint when ready)."""
    cfg_r = await db.execute(text("SELECT target_config FROM scans WHERE id = :id"), {"id": str(scan_id)})
    row = cfg_r.fetchone()
    if not row:
        raise HTTPException(404, "Web scan not found")
    cfg = row.target_config or {}
    base_url = cfg.get("target_url")
    if not base_url:
        raise HTTPException(400, "Scan missing target_url in target_config")
    depth = int(cfg.get("crawl_depth", 3))
    tests = cfg.get("active_tests") or list(OWASP_TESTS.keys())

    await crawl_target(db, scan_id, base_url, depth)
    return await run_owasp_tests(db, scan_id, tests)


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


async def _simulate_crawl(db: AsyncSession, scan_id: UUID, base_url: str, depth: int):
    pages = [base_url.rstrip("/"), f"{base_url.rstrip('/')}/login", f"{base_url.rstrip('/')}/api"]
    pages = pages[: max(1, depth)]
    await db.execute(
        text("""
            INSERT INTO scan_results (scan_id, raw_data, processed_at)
            VALUES (:sid, CAST(:raw AS jsonb), NOW())
        """),
        {"sid": str(scan_id), "raw": json.dumps({"crawled_urls": pages, "depth": depth, "simulated": True})},
    )
    return {"scan_id": str(scan_id), "urls_discovered": len(pages), "urls": pages, "simulated": True}


async def crawl_target(db: AsyncSession, scan_id: UUID, base_url: str, depth: int = 3):
    """Crawl target — real httpx when SCAN_SANDBOX_MODE, simulated only if ALLOW_SIMULATED_SCANS."""
    if not _use_real_engines():
        if _allow_simulated():
            return await _simulate_crawl(db, scan_id, base_url, depth)
        raise HTTPException(503, "Real scan engines require SCAN_SANDBOX_MODE=true")

    try:
        probe = await httpx_probe(base_url)
        crawl = await crawl_urls(base_url, depth=depth)
        raw = {"probe": probe, "crawl": crawl, "engine": "httpx", "simulated": False}
        await db.execute(
            text("""
                INSERT INTO scan_results (scan_id, raw_data, processed_at)
                VALUES (:sid, CAST(:raw AS jsonb), NOW())
            """),
            {"sid": str(scan_id), "raw": json.dumps(raw, default=str)},
        )
        urls = [p.get("url") for p in crawl.get("pages", []) if p.get("url")]
        return {"scan_id": str(scan_id), "urls_discovered": len(urls), "urls": urls, "simulated": False}
    except EngineUnavailableError as exc:
        if _allow_simulated():
            return await _simulate_crawl(db, scan_id, base_url, depth)
        raise HTTPException(503, _engine_unavailable_detail(exc)) from exc


async def _insert_simulated_owasp(db: AsyncSession, scan_id: UUID, tests: list[str], base_url: str) -> int:
    findings = 0
    for test_key in tests:
        meta = OWASP_TESTS.get(test_key)
        if not meta:
            continue
        owasp, title = meta
        await db.execute(
            text("""
                INSERT INTO web_scan_findings (scan_id, url, vulnerability_type, owasp_category, severity, title,
                    description, remediation, is_simulated)
                VALUES (:sid, :url, :vtype, :owasp, 'medium', :title, :desc, :rem, TRUE)
            """),
            {
                "sid": str(scan_id),
                "url": base_url,
                "vtype": test_key,
                "owasp": owasp,
                "title": f"Potential {title}",
                "desc": f"Simulated test '{test_key}' — set SCAN_SANDBOX_MODE and install nuclei for real results.",
                "rem": f"Review and remediate {title.lower()} risks.",
            },
        )
        findings += 1
    return findings


async def run_owasp_tests(db: AsyncSession, scan_id: UUID, tests: list[str]):
    await get_web_scan(db, scan_id)
    cfg_r = await db.execute(text("SELECT target_config FROM scans WHERE id = :id"), {"id": str(scan_id)})
    cfg = cfg_r.fetchone().target_config or {}
    base_url = cfg.get("target_url", "https://example.com")
    findings = 0
    is_simulated = False

    if not _use_real_engines():
        if _allow_simulated():
            findings = await _insert_simulated_owasp(db, scan_id, tests, base_url)
            is_simulated = True
        else:
            raise HTTPException(503, "Real scan engines require SCAN_SANDBOX_MODE=true")
    else:
        nuclei_findings: list[dict] = []
        tags: list[str] = []
        for test_key in tests:
            tags.extend(OWASP_NUCLEI_TAGS.get(test_key, ["misconfig"]))
        tags = list(dict.fromkeys(tags))
        try:
            if engines_status().get("nuclei"):
                nuclei_findings = await run_nuclei(base_url, tags=tags)
            else:
                raise EngineUnavailableError("nuclei not installed")
            for item in nuclei_findings:
                nf = nuclei_to_web_finding(item, base_url)
                await db.execute(
                    text("""
                        INSERT INTO web_scan_findings (scan_id, url, vulnerability_type, owasp_category, severity,
                            title, description, proof, remediation, cwe_id, is_simulated)
                        VALUES (:sid, :url, :vtype, :owasp, :sev, :title, :desc, :proof, :rem, :cwe, FALSE)
                    """),
                    {
                        "sid": str(scan_id),
                        "url": nf["url"],
                        "vtype": nf["vulnerability_type"],
                        "owasp": nf["owasp_category"],
                        "sev": nf["severity"],
                        "title": nf["title"],
                        "desc": nf["description"],
                        "proof": nf.get("proof"),
                        "rem": nf["remediation"],
                        "cwe": nf.get("cwe_id"),
                    },
                )
                findings += 1
        except EngineUnavailableError as exc:
            if _allow_simulated():
                findings = await _insert_simulated_owasp(db, scan_id, tests, base_url)
                is_simulated = True
            else:
                raise HTTPException(503, _engine_unavailable_detail(exc)) from exc

    await db.execute(
        text("UPDATE scans SET findings_count = :fc, status = 'completed', completed_at = NOW() WHERE id = :id"),
        {"id": str(scan_id), "fc": findings},
    )
    await publish_event(
        "webscan.completed",
        {"scan_id": str(scan_id), "findings": findings, "simulated": is_simulated},
    )
    return {"scan_id": str(scan_id), "findings_created": findings, "simulated": is_simulated}


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
