"""Reusable security scan engines for VulnShield workers."""

from vulnshield_common.scan_engines.engines import (
    OWASP_NUCLEI_TAGS,
    EngineUnavailableError,
    crawl_urls,
    dns_lookup,
    engines_status,
    httpx_probe,
    nmap_to_vulnerabilities,
    nuclei_to_web_finding,
    require_engines,
    run_nmap,
    run_nuclei,
    run_semgrep,
)
from vulnshield_common.scan_sandbox import (
    sanitize_log_text as sanitize_for_log,
    truncate_for_storage,
    validate_target_or_raise as validate_scan_target,
)

# Alias used by some handlers
probe_url = httpx_probe

__all__ = [
    "OWASP_NUCLEI_TAGS",
    "EngineUnavailableError",
    "crawl_urls",
    "dns_lookup",
    "engines_status",
    "httpx_probe",
    "probe_url",
    "nmap_to_vulnerabilities",
    "nuclei_to_web_finding",
    "require_engines",
    "run_nmap",
    "run_nuclei",
    "run_semgrep",
    "sanitize_for_log",
    "truncate_for_storage",
    "validate_scan_target",
]
