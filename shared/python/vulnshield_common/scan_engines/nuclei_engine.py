"""Nuclei vulnerability scanner engine."""

from __future__ import annotations

import asyncio
import json
import os

import structlog

from vulnshield_common.scan_sandbox import is_allowed_scan_target, sanitize_log_text

logger = structlog.get_logger()

DEFAULT_TIMEOUT = int(os.getenv("SCAN_ENGINE_TIMEOUT", "600"))

_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "info",
}


def _validate_target(target: str) -> None:
    if not is_allowed_scan_target(target):
        raise ValueError("Target not allowed in sandbox mode.")


def _normalize_finding(raw: dict, url: str) -> dict:
    info = raw.get("info", {}) if isinstance(raw.get("info"), dict) else {}
    sev = _SEVERITY_MAP.get(str(info.get("severity", "info")).lower(), "info")
    template_id = raw.get("template-id") or raw.get("templateID") or "nuclei-finding"
    return {
        "url": raw.get("host") or raw.get("matched-at") or url,
        "vulnerability_type": template_id,
        "owasp_category": info.get("tags", [None])[0] if isinstance(info.get("tags"), list) else None,
        "severity": sev,
        "title": str(info.get("name", template_id))[:500],
        "description": info.get("description"),
        "proof": sanitize_log_text(raw.get("matcher-name") or raw.get("type") or ""),
        "cwe_id": None,
        "remediation": info.get("remediation"),
    }


async def run_nuclei(url: str, timeout: int | None = None) -> list[dict]:
    """Run nuclei against URL with JSON output."""
    _validate_target(url)
    timeout = timeout or DEFAULT_TIMEOUT

    cmd = [
        "nuclei", "-u", url, "-jsonl", "-silent",
        "-severity", "critical,high,medium,low,info",
        "-no-color",
    ]
    logger.info("nuclei_start", url=url)

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        logger.error("nuclei_timeout", url=url)
        raise RuntimeError(f"nuclei timed out after {timeout}s")

    if proc.returncode not in (0, 1):
        err = sanitize_log_text(stderr.decode(errors="replace"))
        logger.warning("nuclei_nonzero_exit", url=url, exit_code=proc.returncode, stderr=err)

    findings: list[dict] = []
    for line in stdout.decode(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
            if isinstance(raw, dict):
                findings.append(_normalize_finding(raw, url))
        except json.JSONDecodeError:
            continue

    logger.info("nuclei_complete", url=url, findings=len(findings))
    return findings
