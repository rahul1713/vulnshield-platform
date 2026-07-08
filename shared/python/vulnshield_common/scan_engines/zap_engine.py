"""OWASP ZAP API scanner with nuclei+httpx fallback."""

from __future__ import annotations

import asyncio
import os
from typing import Any

import httpx
import structlog

from vulnshield_common.scan_engines.httpx_probe import probe_url
from vulnshield_common.scan_engines.nuclei_engine import run_nuclei
from vulnshield_common.scan_sandbox import is_allowed_scan_target, sanitize_log_text

logger = structlog.get_logger()

DEFAULT_TIMEOUT = int(os.getenv("ZAP_SCAN_TIMEOUT", "900"))


def _zap_base_url() -> str | None:
    url = os.getenv("ZAP_BASE_URL", "").strip()
    return url.rstrip("/") if url else None


async def _run_zap_api(url: str, timeout: int) -> list[dict]:
    base = _zap_base_url()
    if not base:
        return []

    if not is_allowed_scan_target(url):
        raise ValueError("Target not allowed in sandbox mode.")

    findings: list[dict] = []
    async with httpx.AsyncClient(timeout=30.0) as client:
        spider_resp = await client.get(
            f"{base}/JSON/spider/action/scan/",
            params={"url": url, "maxChildren": "5"},
        )
        spider_resp.raise_for_status()
        scan_id = spider_resp.json().get("scan")

        if scan_id:
            elapsed = 0
            while elapsed < timeout:
                status_resp = await client.get(
                    f"{base}/JSON/spider/view/status/",
                    params={"scanId": scan_id},
                )
                status_resp.raise_for_status()
                if int(status_resp.json().get("status", "100")) >= 100:
                    break
                await asyncio.sleep(2)
                elapsed += 2

        ascan_resp = await client.get(
            f"{base}/JSON/ascan/action/scan/",
            params={"url": url, "recurse": "true"},
        )
        ascan_resp.raise_for_status()
        ascan_id = ascan_resp.json().get("scan")

        if ascan_id:
            elapsed = 0
            while elapsed < timeout:
                status_resp = await client.get(
                    f"{base}/JSON/ascan/view/status/",
                    params={"scanId": ascan_id},
                )
                status_resp.raise_for_status()
                if int(status_resp.json().get("status", "100")) >= 100:
                    break
                await asyncio.sleep(3)
                elapsed += 3

        alerts_resp = await client.get(f"{base}/JSON/core/view/alerts/", params={"baseurl": url})
        alerts_resp.raise_for_status()
        alerts: list[dict[str, Any]] = alerts_resp.json().get("alerts", [])

        for alert in alerts:
            risk = str(alert.get("risk", "Low")).lower()
            sev_map = {"high": "high", "medium": "medium", "low": "low", "informational": "info"}
            findings.append({
                "url": alert.get("url", url),
                "vulnerability_type": alert.get("pluginId", "zap"),
                "severity": sev_map.get(risk, "medium"),
                "title": str(alert.get("name", "ZAP alert"))[:500],
                "description": alert.get("desc"),
                "proof": sanitize_log_text(alert.get("evidence")),
                "remediation": alert.get("solution"),
                "cwe_id": alert.get("cweid"),
            })

    logger.info("zap_complete", url=url, findings=len(findings))
    return findings


async def run_zap_scan(url: str, timeout: int | None = None) -> list[dict]:
    """Run ZAP scan when ZAP_BASE_URL is set; otherwise nuclei + httpx fallback."""
    timeout = timeout or DEFAULT_TIMEOUT
    if _zap_base_url():
        try:
            return await _run_zap_api(url, timeout)
        except Exception as exc:
            logger.warning("zap_failed_fallback", url=url, error=sanitize_log_text(str(exc)))

    nuclei_findings = await run_nuclei(url, timeout=min(timeout, 600))
    probe = await probe_url(url)
    return nuclei_findings + probe.get("findings", [])
