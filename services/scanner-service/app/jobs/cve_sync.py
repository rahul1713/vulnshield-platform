"""Sync recent CVEs from NVD into the cves table."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from datetime import datetime, timedelta, timezone

import httpx
import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from vulnshield_common.config import get_settings

logger = structlog.get_logger()

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _parse_nvd_cve(item: dict) -> dict | None:
    cve = item.get("cve", {})
    cve_id = cve.get("id")
    if not cve_id:
        return None

    descriptions = cve.get("descriptions") or []
    description = next((d.get("value") for d in descriptions if d.get("lang") == "en"), None)

    cvss_v3_score = None
    cvss_v3_vector = None
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData", {})
            cvss_v3_score = data.get("baseScore")
            cvss_v3_vector = data.get("vectorString")
            break

    cwe_ids = []
    for weakness in cve.get("weaknesses") or []:
        for desc in weakness.get("description") or []:
            val = desc.get("value", "")
            if val.startswith("CWE-"):
                cwe_ids.append(val)

    references = [r.get("url") for r in cve.get("references") or [] if r.get("url")]

    published = cve.get("published", "")[:10] or None
    modified = cve.get("lastModified", "")[:10] or None

    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_v3_score": cvss_v3_score,
        "cvss_v3_vector": cvss_v3_vector,
        "cwe_ids": json.dumps(cwe_ids),
        "references": json.dumps(references),
        "published_date": published,
        "last_modified": modified,
        "cpes": json.dumps([]),
    }


async def fetch_recent_cves(days: int = 7, limit: int = 500) -> list[dict]:
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT00:00:00.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT23:59:59.999"),
        "resultsPerPage": min(limit, 2000),
    }
    api_key = os.getenv("NVD_API_KEY", "").strip()
    headers = {"apiKey": api_key} if api_key else {}

    async with httpx.AsyncClient(timeout=120.0) as client:
        response = await client.get(NVD_API_URL, params=params, headers=headers)
        response.raise_for_status()
        payload = response.json()

    vulnerabilities = payload.get("vulnerabilities") or []
    parsed: list[dict] = []
    for item in vulnerabilities[:limit]:
        row = _parse_nvd_cve(item)
        if row:
            parsed.append(row)
    return parsed


async def upsert_cves(db: AsyncSession, rows: list[dict]) -> int:
    count = 0
    for row in rows:
        await db.execute(
            text("""
                INSERT INTO cves (cve_id, description, cvss_v3_score, cvss_v3_vector,
                    cwe_ids, references, cpes, published_date, last_modified)
                VALUES (:cve_id, :description, :cvss_v3_score, :cvss_v3_vector,
                    CAST(:cwe_ids AS jsonb), CAST(:references AS jsonb), CAST(:cpes AS jsonb),
                    CAST(:published_date AS date), CAST(:last_modified AS date))
                ON CONFLICT (cve_id) DO UPDATE SET
                    description = EXCLUDED.description,
                    cvss_v3_score = EXCLUDED.cvss_v3_score,
                    cvss_v3_vector = EXCLUDED.cvss_v3_vector,
                    cwe_ids = EXCLUDED.cwe_ids,
                    references = EXCLUDED.references,
                    last_modified = EXCLUDED.last_modified,
                    updated_at = NOW()
            """),
            row,
        )
        count += 1
    await db.commit()
    return count


async def run_sync(days: int = 7, limit: int = 500) -> dict:
    settings = get_settings()
    engine = create_async_engine(settings.database_url, echo=False)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    logger.info("cve_sync_starting", days=days, limit=limit)
    rows = await fetch_recent_cves(days=days, limit=limit)
    async with session_factory() as db:
        upserted = await upsert_cves(db, rows)
    await engine.dispose()
    logger.info("cve_sync_complete", fetched=len(rows), upserted=upserted)
    return {"fetched": len(rows), "upserted": upserted}


def main() -> None:
    parser = argparse.ArgumentParser(description="Sync recent CVEs from NVD")
    parser.add_argument("--days", type=int, default=int(os.getenv("CVE_SYNC_DAYS", "7")))
    parser.add_argument("--limit", type=int, default=int(os.getenv("CVE_SYNC_LIMIT", "500")))
    args = parser.parse_args()
    result = asyncio.run(run_sync(days=args.days, limit=args.limit))
    print(json.dumps(result))


if __name__ == "__main__":
    main()
