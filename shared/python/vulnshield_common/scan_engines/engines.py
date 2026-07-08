"""Real scanning engines — httpx, nuclei, nmap, semgrep, DNS (local subprocess only)."""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import socket
import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
import structlog

logger = structlog.get_logger()

LINK_RE = re.compile(r"""href=["']([^"'#]+)["']""", re.I)


class EngineUnavailableError(RuntimeError):
    """Raised when a required scanning engine binary is not installed or failed."""


def _which(cmd: str) -> str | None:
    return shutil.which(cmd)


def engines_status() -> dict[str, bool]:
    return {
        "httpx_lib": True,
        "nuclei": _which("nuclei") is not None,
        "nmap": _which("nmap") is not None,
        "semgrep": _which("semgrep") is not None,
    }


def require_engines(*names: str) -> None:
    status = engines_status()
    missing = [n for n in names if not status.get(n)]
    if missing:
        raise EngineUnavailableError(
            f"Required scan engine(s) unavailable: {', '.join(missing)}. "
            "Install nuclei/nmap/semgrep or set ALLOW_SIMULATED_SCANS=true for development fallback."
        )


async def _run_cmd(cmd: list[str], timeout: float = 300.0) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError as exc:
        proc.kill()
        raise EngineUnavailableError(f"Command timed out: {' '.join(cmd)}") from exc
    return proc.returncode or 0, stdout_b.decode(errors="replace"), stderr_b.decode(errors="replace")


async def httpx_probe(url: str, timeout: float = 15.0) -> dict[str, Any]:
    """HTTP probe using the httpx library (not ProjectDiscovery httpx)."""
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False) as client:
        try:
            resp = await client.get(url)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return {
                "url": str(resp.url),
                "status_code": resp.status_code,
                "headers": headers,
                "title": _extract_title(resp.text),
                "content_length": len(resp.content),
                "technologies": _guess_tech(headers, resp.text),
            }
        except httpx.HTTPError as exc:
            return {"url": url, "error": str(exc)}


def _extract_title(html: str) -> str | None:
    m = re.search(r"<title[^>]*>([^<]+)</title>", html, re.I)
    return m.group(1).strip()[:200] if m else None


def _guess_tech(headers: dict[str, str], html: str) -> list[str]:
    tech: list[str] = []
    server = headers.get("server", "")
    if server:
        tech.append(f"server:{server[:80]}")
    if "set-cookie" in headers:
        tech.append("cookies")
    if "x-powered-by" in headers:
        tech.append(f"powered-by:{headers['x-powered-by'][:40]}")
    if "wp-content" in html:
        tech.append("wordpress")
    return tech


async def crawl_urls(base_url: str, depth: int = 3, max_pages: int = 50) -> dict[str, Any]:
    """Crawl target with httpx — same-origin links only."""
    parsed = urlparse(base_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("URL must be http or https")

    origin = f"{parsed.scheme}://{parsed.netloc}"
    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(base_url.rstrip("/"), 0)]
    pages: list[dict[str, Any]] = []

    async with httpx.AsyncClient(timeout=20.0, follow_redirects=True, verify=False) as client:
        while queue and len(pages) < max_pages:
            url, d = queue.pop(0)
            norm = url.split("#")[0].rstrip("/")
            if norm in visited or d > depth:
                continue
            visited.add(norm)
            try:
                resp = await client.get(url)
                page = {
                    "url": str(resp.url),
                    "status_code": resp.status_code,
                    "depth": d,
                }
                pages.append(page)
                if d < depth and "text/html" in resp.headers.get("content-type", ""):
                    for href in LINK_RE.findall(resp.text):
                        if href.startswith(("mailto:", "javascript:", "data:")):
                            continue
                        full = urljoin(str(resp.url), href)
                        fp = urlparse(full)
                        if f"{fp.scheme}://{fp.netloc}" == origin:
                            queue.append((full, d + 1))
            except httpx.HTTPError as exc:
                pages.append({"url": url, "error": str(exc), "depth": d})

    return {"base_url": base_url, "depth": depth, "urls_discovered": len(pages), "pages": pages}


async def run_nuclei(target: str, tags: list[str] | None = None, severity: str | None = None) -> list[dict[str, Any]]:
    """Run nuclei with JSON output. Uses safe/passive tags by default."""
    from vulnshield_common.scan_sandbox import validate_target_or_raise
    validate_target_or_raise(target)
    require_engines("nuclei")
    cmd = ["nuclei", "-u", target, "-jsonl", "-silent", "-no-color"]
    if tags:
        cmd.extend(["-tags", ",".join(tags)])
    else:
        cmd.extend(["-tags", "safe,passive,tech"])
    if severity:
        cmd.extend(["-severity", severity])

    code, stdout, stderr = await _run_cmd(cmd, timeout=600.0)
    if code not in (0, 1):
        raise EngineUnavailableError(f"nuclei failed (exit {code}): {stderr[:500]}")

    findings: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return findings


async def run_nmap(target: str, top_ports: int = 100) -> dict[str, Any]:
    """Run nmap top-port scan with XML output."""
    require_engines("nmap")
    cmd = ["nmap", "-oX", "-", "--top-ports", str(top_ports), "-Pn", target]
    code, stdout, stderr = await _run_cmd(cmd, timeout=600.0)
    if code != 0:
        raise EngineUnavailableError(f"nmap failed (exit {code}): {stderr[:500]}")
    return _parse_nmap_xml(stdout)


def _parse_nmap_xml(xml_text: str) -> dict[str, Any]:
    hosts: list[dict[str, Any]] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return {"hosts": [], "raw_error": "invalid nmap xml"}

    for host in root.findall("host"):
        addr_el = host.find("address[@addrtype='ipv4']") or host.find("address")
        addr = addr_el.get("addr") if addr_el is not None else None
        ports: list[dict[str, Any]] = []
        ports_el = host.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                svc_el = port_el.find("service")
                ports.append(
                    {
                        "port": int(port_el.get("portid", 0)),
                        "protocol": port_el.get("protocol", "tcp"),
                        "state": state_el.get("state") if state_el is not None else "unknown",
                        "service": svc_el.get("name") if svc_el is not None else None,
                        "version": svc_el.get("version") if svc_el is not None else None,
                    }
                )
        hosts.append({"address": addr, "ports": ports})
    return {"hosts": hosts}


async def run_semgrep(path: str, config: str = "auto") -> list[dict[str, Any]]:
    """Run semgrep on a directory and return normalized findings."""
    require_engines("semgrep")
    cmd = ["semgrep", "--config", config, "--json", "--quiet", path]
    code, stdout, stderr = await _run_cmd(cmd, timeout=600.0)
    if code not in (0, 1):
        raise EngineUnavailableError(f"semgrep failed (exit {code}): {stderr[:500]}")

    try:
        data = json.loads(stdout) if stdout.strip() else {}
    except json.JSONDecodeError:
        return []

    findings: list[dict[str, Any]] = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        sev = extra.get("severity", "WARNING").lower()
        severity_map = {"error": "high", "warning": "medium", "info": "low"}
        findings.append(
            {
                "title": extra.get("message", r.get("check_id", "semgrep finding")),
                "severity": severity_map.get(sev, "medium"),
                "category": "SAST",
                "file_path": r.get("path"),
                "line_start": r.get("start", {}).get("line"),
                "line_end": r.get("end", {}).get("line"),
                "description": extra.get("message"),
                "recommended_fix": extra.get("fix"),
                "cwe_id": (extra.get("metadata") or {}).get("cwe"),
                "rule_id": r.get("check_id"),
            }
        )
    return findings


def dns_lookup(hostname: str) -> dict[str, Any]:
    """Resolve hostname to A/AAAA records."""
    records: list[str] = []
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(hostname, None):
            if family == socket.AF_INET:
                records.append(sockaddr[0])
            elif family == socket.AF_INET6:
                records.append(sockaddr[0])
    except socket.gaierror as exc:
        return {"hostname": hostname, "error": str(exc), "records": []}
    return {"hostname": hostname, "records": sorted(set(records))}


def nuclei_to_web_finding(item: dict[str, Any], base_url: str) -> dict[str, Any]:
    """Normalize nuclei JSONL output to web_scan_findings shape."""
    info = item.get("info", {})
    sev = (info.get("severity") or "medium").lower()
    if sev not in ("critical", "high", "medium", "low", "info"):
        sev = "medium"
    tags = info.get("tags") or []
    owasp = next((t for t in tags if t.startswith("owasp")), None)
    return {
        "url": item.get("matched-at") or item.get("host") or base_url,
        "vulnerability_type": item.get("template-id", "nuclei"),
        "owasp_category": owasp or "A05:2021-Security Misconfiguration",
        "severity": sev,
        "title": info.get("name", item.get("template-id", "Nuclei finding")),
        "description": info.get("description") or info.get("name", ""),
        "proof": json.dumps(item.get("matcher-name") or item.get("curl-command") or "")[:2000],
        "remediation": info.get("remediation") or "Review nuclei template guidance and remediate misconfiguration.",
        "cwe_id": (info.get("classification") or {}).get("cwe-id"),
        "is_simulated": False,
    }


def nmap_to_vulnerabilities(nmap_result: dict[str, Any], asset_id: str | None) -> list[dict[str, Any]]:
    """Convert open ports to informational vulnerability records."""
    vulns: list[dict[str, Any]] = []
    for host in nmap_result.get("hosts", []):
        for port in host.get("ports", []):
            if port.get("state") != "open":
                continue
            svc = port.get("service") or "unknown"
            vulns.append(
                {
                    "title": f"Open port {port['port']}/{port.get('protocol', 'tcp')} ({svc})",
                    "severity": "info",
                    "category": "network_discovery",
                    "description": f"Nmap discovered open port {port['port']} running {svc}.",
                    "port": port["port"],
                    "protocol": port.get("protocol", "tcp"),
                    "affected_software": svc,
                    "affected_version": port.get("version"),
                    "metadata": {"engine": "nmap", "asset_id": asset_id},
                }
            )
    return vulns


OWASP_NUCLEI_TAGS = {
    "sqli": ["sqli", "injection"],
    "xss": ["xss"],
    "csrf": ["csrf"],
    "ssrf": ["ssrf"],
    "xxe": ["xxe"],
    "idor": ["idor", "auth-bypass"],
    "auth": ["auth", "default-login"],
    "misconfig": ["misconfig", "exposure"],
    "sensitive": ["exposure", "tokens"],
    "components": ["cve", "tech"],
}
