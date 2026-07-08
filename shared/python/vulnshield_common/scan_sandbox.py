"""Scan target allowlisting for sandbox / zero-leakage deployments."""

from __future__ import annotations

import ipaddress
import os
import re
from urllib.parse import urlparse

from fastapi import HTTPException

_RFC1918 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)

_LOCAL_HOSTNAMES = frozenset({"localhost", "localhost.localdomain"})
_LOOPBACK_LITERALS = frozenset({"127.0.0.1", "::1", "0:0:0:0:0:0:0:1"})

_DOCKER_INTERNAL_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$", re.IGNORECASE)


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def is_scan_sandbox_mode() -> bool:
    return _env_bool("SCAN_SANDBOX_MODE", default=False)


def allow_external_targets() -> bool:
    """When true, skip allowlist checks. Defaults false in sandbox mode."""
    if is_scan_sandbox_mode():
        return _env_bool("ALLOW_EXTERNAL_TARGETS", default=False)
    return _env_bool("ALLOW_EXTERNAL_TARGETS", default=True)


def sandbox_allow_private() -> bool:
    return _env_bool("SANDBOX_ALLOW_PRIVATE", default=False)


def allow_simulated_scans() -> bool:
    return _env_bool("ALLOW_SIMULATED_SCANS", default=not is_scan_sandbox_mode())


def _extract_host(url_or_host: str) -> str:
    value = (url_or_host or "").strip()
    if not value:
        return ""
    if "://" in value:
        parsed = urlparse(value)
        return (parsed.hostname or "").lower().rstrip(".")
    if value.startswith("["):
        end = value.find("]")
        if end != -1:
            return value[1:end].lower()
    # host:port — only split when a single colon separates host from numeric port
    if value.count(":") == 1:
        host, _, port = value.rpartition(":")
        if port.isdigit():
            return host.lower().rstrip(".")
    return value.lower().rstrip(".")


def _is_rfc1918(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if not isinstance(ip, ipaddress.IPv4Address):
        return False
    return any(ip in net for net in _RFC1918)


def _is_docker_internal_host(host: str) -> bool:
    if host.endswith(".vulnshield-net"):
        return True
    if host.endswith(".local"):
        return True
    return bool(_DOCKER_INTERNAL_RE.match(host)) and "." not in host


def is_allowed_scan_target(url_or_host: str) -> bool:
    """Return True when the target is permitted in the current sandbox policy."""
    if allow_external_targets():
        return True

    host = _extract_host(url_or_host)
    if not host:
        return False

    if host in _LOCAL_HOSTNAMES or host in _LOOPBACK_LITERALS:
        return True

    if host.endswith(".local"):
        return True

    if _is_docker_internal_host(host):
        return True

    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback:
            return True
        if sandbox_allow_private() and _is_rfc1918(ip):
            return True
        return False
    except ValueError:
        pass

    return False


def validate_target_or_raise(target: str, *, field: str = "target") -> str:
    """Validate scan target; raise HTTPException when disallowed."""
    normalized = (target or "").strip()
    if not normalized:
        raise HTTPException(400, f"{field} is required")
    if not is_allowed_scan_target(normalized):
        raise HTTPException(
            403,
            f"Scan target not allowed in sandbox mode: {normalized}. "
            "Permitted: localhost, 127.0.0.1, ::1, *.local, *.vulnshield-net, "
            "docker-internal hostnames, and RFC1918 when SANDBOX_ALLOW_PRIVATE=true.",
        )
    return normalized


def extract_targets_from_config(target_config: dict) -> list[str]:
    """Collect host/URL values from a scan target_config payload."""
    keys = ("target_url", "url", "host", "hostname", "ip", "ip_address", "target_host", "address")
    found: list[str] = []
    for key in keys:
        val = target_config.get(key)
        if isinstance(val, str) and val.strip():
            found.append(val.strip())
    targets = target_config.get("targets") or target_config.get("hosts")
    if isinstance(targets, list):
        for item in targets:
            if isinstance(item, str) and item.strip():
                found.append(item.strip())
            elif isinstance(item, dict):
                found.extend(extract_targets_from_config(item))
    return found


def validate_scan_config_or_raise(target_config: dict) -> None:
    """Validate all targets embedded in a scan configuration."""
    if allow_external_targets():
        return
    for target in extract_targets_from_config(target_config or {}):
        validate_target_or_raise(target, field="target_config")


def sanitize_log_text(text: str | None, max_len: int = 200) -> str:
    """Truncate sensitive content before logging."""
    if not text:
        return ""
    cleaned = re.sub(r"\s+", " ", str(text)).strip()
    if len(cleaned) <= max_len:
        return cleaned
    return cleaned[:max_len] + "…[truncated]"


def truncate_for_storage(text: str | None, max_len: int = 4096) -> str | None:
    if text is None:
        return None
    if len(text) <= max_len:
        return text
    return text[:max_len] + "\n…[truncated]"


def normalize_cwe_id(value: str | list | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        return str(value[0])[:20] if value else None
    return str(value)[:20]
