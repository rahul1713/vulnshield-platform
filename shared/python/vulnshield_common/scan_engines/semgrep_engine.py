"""Semgrep static analysis engine."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import structlog

from vulnshield_common.scan_sandbox import sanitize_log_text

logger = structlog.get_logger()

DEFAULT_TIMEOUT = int(os.getenv("SCAN_ENGINE_TIMEOUT", "600"))

_SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}


async def run_semgrep(directory: str, timeout: int | None = None) -> list[dict]:
    """Run semgrep --json on a directory; never logs source code."""
    timeout = timeout or DEFAULT_TIMEOUT
    path = Path(directory).resolve()
    if not path.is_dir():
        raise ValueError(f"Semgrep directory not found: {directory}")

    cmd = ["semgrep", "--json", "--quiet", "--metrics", "off", str(path)]
    logger.info("semgrep_start", directory=str(path))

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
        logger.error("semgrep_timeout", directory=str(path))
        raise RuntimeError(f"semgrep timed out after {timeout}s")

    if proc.returncode not in (0, 1):
        err = sanitize_log_text(stderr.decode(errors="replace"))
        logger.warning("semgrep_nonzero_exit", directory=str(path), exit_code=proc.returncode, stderr=err)

    findings: list[dict] = []
    try:
        data = json.loads(stdout.decode(errors="replace") or "{}")
    except json.JSONDecodeError:
        logger.warning("semgrep_json_parse_failed", directory=str(path))
        return findings

    for result in data.get("results", []):
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {}) if isinstance(extra.get("metadata"), dict) else {}
        sev = _SEVERITY_MAP.get(str(extra.get("severity", "INFO")).upper(), "medium")
        findings.append({
            "file_path": result.get("path", "unknown"),
            "line_start": result.get("start", {}).get("line"),
            "line_end": result.get("end", {}).get("line"),
            "severity": sev,
            "category": metadata.get("category", "security"),
            "title": str(extra.get("message", result.get("check_id", "Semgrep finding")))[:500],
            "description": extra.get("message"),
            "cwe_id": metadata.get("cwe") or metadata.get("cwe_id"),
            "owasp_category": metadata.get("owasp"),
            "recommended_fix": extra.get("fix"),
        })

    logger.info("semgrep_complete", directory=str(path), findings=len(findings))
    return findings
