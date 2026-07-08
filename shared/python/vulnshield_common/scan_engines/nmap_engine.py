"""Nmap port/service scanner engine."""

from __future__ import annotations

import asyncio
import os
import xml.etree.ElementTree as ET

import structlog

from vulnshield_common.scan_sandbox import is_allowed_scan_target, sanitize_log_text

logger = structlog.get_logger()

DEFAULT_TIMEOUT = int(os.getenv("SCAN_ENGINE_TIMEOUT", "300"))


def _validate_target(target: str) -> None:
    if not is_allowed_scan_target(target):
        raise ValueError(
            "Target not allowed in sandbox mode. "
            "Use localhost, RFC1918, *.vulnshield.local, or internal service names."
        )


def _parse_nmap_xml(xml_text: str, host: str) -> list[dict]:
    findings: list[dict] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        logger.warning("nmap_xml_parse_failed")
        return findings

    for host_el in root.findall("host"):
        addr_el = host_el.find("address[@addrtype='ipv4']") or host_el.find("address[@addrtype='ipv6']")
        address = addr_el.get("addr") if addr_el is not None else host
        for port_el in host_el.findall(".//port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            port_num = int(port_el.get("portid", "0"))
            protocol = port_el.get("protocol", "tcp")
            service_el = port_el.find("service")
            service_name = service_el.get("name", "unknown") if service_el is not None else "unknown"
            service_version = ""
            if service_el is not None:
                product = service_el.get("product", "")
                version = service_el.get("version", "")
                service_version = f"{product} {version}".strip()
            findings.append({
                "host": address,
                "port": port_num,
                "protocol": protocol,
                "service_name": service_name,
                "service_version": service_version,
                "title": f"Open port {port_num}/{protocol}: {service_name}",
                "severity": "medium" if port_num in (22, 3389, 445) else "low",
                "description": f"Nmap detected open {service_name} on port {port_num}/{protocol}.",
            })
    return findings


async def run_nmap(target: str, timeout: int | None = None) -> list[dict]:
    """Run nmap -sV against target; returns parsed open-port findings."""
    _validate_target(target)
    timeout = timeout or DEFAULT_TIMEOUT
    host = target.split("://")[-1].split("/")[0].split(":")[0]

    cmd = ["nmap", "-sV", "-T4", "--open", "-oX", "-", "-Pn", host]
    logger.info("nmap_start", target=host)

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
        logger.error("nmap_timeout", target=host)
        raise RuntimeError(f"nmap timed out after {timeout}s")

    if proc.returncode not in (0, 1):
        err = sanitize_log_text(stderr.decode(errors="replace"))
        logger.error("nmap_failed", target=host, exit_code=proc.returncode, stderr=err)
        raise RuntimeError(f"nmap failed (exit {proc.returncode})")

    findings = _parse_nmap_xml(stdout.decode(errors="replace"), host)
    logger.info("nmap_complete", target=host, open_ports=len(findings))
    return findings
