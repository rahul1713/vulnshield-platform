"""HTTP HEAD/GET probe for web targets (curl-based)."""

from __future__ import annotations

import asyncio
import os
import re

import structlog

from vulnshield_common.scan_sandbox import is_allowed_scan_target, sanitize_log_text

logger = structlog.get_logger()

DEFAULT_TIMEOUT = int(os.getenv("HTTP_PROBE_TIMEOUT", "30"))

_SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)


def _validate_target(target: str) -> None:
    if not is_allowed_scan_target(target):
        raise ValueError("Target not allowed in sandbox mode.")


def _parse_curl_headers(output: str) -> dict:
    headers: dict[str, str] = {}
    status_code = 0
    for line in output.splitlines():
        if line.upper().startswith("HTTP/"):
            match = re.search(r"HTTP/\d(?:\.\d)?\s+(\d+)", line)
            if match:
                status_code = int(match.group(1))
        elif ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()
    return {"status_code": status_code, "headers": headers}


async def probe_url(url: str, timeout: int | None = None) -> dict:
    """Probe URL with curl -sI and return status, headers, and security findings."""
    _validate_target(url)
    timeout = timeout or DEFAULT_TIMEOUT

    cmd = ["curl", "-sI", "-L", "-m", str(timeout), url]
    logger.info("httpx_probe_start", url=url)

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout + 5)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        logger.error("httpx_probe_timeout", url=url)
        raise RuntimeError(f"HTTP probe timed out after {timeout}s")

    output = stdout.decode(errors="replace")
    parsed = _parse_curl_headers(output)

    missing_headers = [h for h in _SECURITY_HEADERS if h not in parsed["headers"]]
    findings: list[dict] = []
    if missing_headers:
        findings.append({
            "url": url,
            "vulnerability_type": "missing-security-headers",
            "severity": "low",
            "title": "Missing security headers",
            "description": f"Response is missing recommended headers: {', '.join(missing_headers)}",
            "proof": sanitize_log_text(f"status={parsed['status_code']}, missing={missing_headers}"),
            "remediation": "Configure HSTS, CSP, X-Frame-Options, and related headers.",
        })

    server = parsed["headers"].get("server", "")
    if server:
        findings.append({
            "url": url,
            "vulnerability_type": "server-banner",
            "severity": "info",
            "title": "Server banner disclosed",
            "description": f"Server header reveals: {sanitize_log_text(server, 80)}",
            "proof": sanitize_log_text(server, 80),
            "remediation": "Minimize or remove Server header disclosure.",
        })

    logger.info(
        "httpx_probe_complete",
        url=url,
        status=parsed["status_code"],
        findings=len(findings),
    )
    return {
        "url": url,
        "status_code": parsed["status_code"],
        "headers": {k: sanitize_log_text(v, 120) for k, v in parsed["headers"].items()},
        "findings": findings,
        "stderr": sanitize_log_text(stderr.decode(errors="replace")),
    }
