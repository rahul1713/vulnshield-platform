"""Local Qwen orchestration for scan planning and finding triage."""

from __future__ import annotations

import json
import re
from typing import Any

from vulnshield_common.llm import SecurityLLMConfigurationError, get_local_security_llm_provider

_SECRET_PATTERNS = [
  re.compile(r"(?i)(api[_-]?key|secret|password|token|authorization)\s*[:=]\s*\S+"),
  re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----"),
  re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
]


def sanitize_for_llm(text: str, max_chars: int = 4000) -> str:
    redacted = text
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted[:max_chars]


async def plan_scan(scan_type: str, target: str, context: dict[str, Any] | None = None) -> dict:
    llm = get_local_security_llm_provider()
    system = (
        "You are a senior AppSec architect. Return JSON with keys: "
        "engines (list of: nmap, nuclei, semgrep, httpx), "
        "priority (critical|high|medium|low), steps (list of short strings), "
        "scope_notes (string). Use only safe, authorized testing."
    )
    user = sanitize_for_llm(
        f"Scan type: {scan_type}\nTarget: {target}\nContext: {json.dumps(context or {})}"
    )
    return await llm.generate_json(system, user)


async def triage_findings(findings: list[dict]) -> list[dict]:
    if not findings:
        return []
    llm = get_local_security_llm_provider()
    summary = sanitize_for_llm(json.dumps(findings[:50], default=str))
    system = (
        "Triage security findings. Return JSON with key 'findings': same list enriched with "
        "'priority_rank' (int), 'exploitability' (low|medium|high), 'business_risk' (string)."
    )
    try:
        result = await llm.generate_json(system, summary)
        enriched = result.get("findings", findings)
        return enriched if isinstance(enriched, list) else findings
    except SecurityLLMConfigurationError:
        return findings
