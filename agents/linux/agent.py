#!/usr/bin/env python3
"""VulnShield Linux Agent - inventory collection and platform communication."""

from __future__ import annotations

import hashlib
import logging
import socket
import ssl
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import httpx

from collectors import collect_all
from config import AgentSettings, get_settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("vulnshield-agent")


class VulnShieldAgent:
    """Linux endpoint agent for VulnShield Platform."""

    def __init__(self, settings: AgentSettings | None = None):
        self.settings = settings or get_settings()
        logging.getLogger().setLevel(self.settings.log_level.upper())
        self.agent_id = self.settings.agent_id or self._generate_agent_id()
        self._client: httpx.Client | None = None

    def _generate_agent_id(self) -> str:
        hostname = socket.gethostname()
        machine_id = ""
        for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            try:
                machine_id = Path(path).read_text().strip()
                break
            except OSError:
                continue
        raw = f"{hostname}:{machine_id}:{uuid.getnode()}"
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    def _build_ssl_context(self) -> ssl.SSLContext | bool:
        if not self.settings.mtls_enabled:
            return self.settings.verify_ssl

        ctx = ssl.create_default_context(cafile=str(self.settings.ca_cert))
        ctx.load_cert_chain(
            certfile=str(self.settings.client_cert),
            keyfile=str(self.settings.client_key),
        )
        ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx

    def _get_client(self) -> httpx.Client:
        if self._client is None:
            headers: dict[str, str] = {}
            token = self.settings.agent_token or self.settings.api_token
            if token:
                headers["X-Agent-Token"] = token
                headers["Authorization"] = f"Bearer {token}"

            self._client = httpx.Client(
                base_url=self.settings.api_url.rstrip("/"),
                headers=headers,
                timeout=httpx.Timeout(60.0, connect=10.0),
                verify=self._build_ssl_context(),
            )
        return self._client

    def _post(self, path: str, payload: dict) -> httpx.Response:
        client = self._get_client()
        response = client.post(path, json=payload)
        response.raise_for_status()
        return response

    def register(self) -> dict:
        """Register agent with the VulnShield asset service."""
        payload = {
            "agent_id": self.agent_id,
            "hostname": socket.gethostname(),
            "platform": self.settings.platform,
            "version": self.settings.version,
            "ip_address": self._get_primary_ip(),
            "metadata": {
                "mtls_enabled": self.settings.mtls_enabled,
                "registered_at": datetime.now(timezone.utc).isoformat(),
            },
        }
        logger.info("Registering agent %s", self.agent_id)
        response = self._post("/agents/machine/register", payload)
        return response.json()

    def heartbeat(self) -> dict:
        """Send heartbeat to keep agent status online."""
        payload = {
            "agent_id": self.agent_id,
            "status": "online",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ip_address": self._get_primary_ip(),
        }
        response = self._post("/agents/machine/heartbeat", payload)
        return response.json()

    def send_inventory(self) -> dict:
        """Collect and upload full system inventory."""
        logger.info("Collecting inventory...")
        inventory = collect_all()
        payload = {
            "agent_id": self.agent_id,
            "scan_data": {
                "platform": self.settings.platform,
                "collected_at": datetime.now(timezone.utc).isoformat(),
                "inventory": inventory,
            },
        }
        logger.info("Uploading inventory (%d categories)", len(inventory))
        response = self._post("/ingestion/agent", payload)
        return response.json()

    def _get_primary_ip(self) -> str | None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except OSError:
            return None

    def run(self) -> None:
        """Main agent loop: register, then heartbeat + inventory on intervals."""
        try:
            self.register()
        except httpx.HTTPError as exc:
            logger.warning("Registration failed (will retry): %s", exc)

        last_inventory = 0.0
        while True:
            try:
                self.heartbeat()
                logger.debug("Heartbeat sent")
            except httpx.HTTPError as exc:
                logger.error("Heartbeat failed: %s", exc)

            now = time.monotonic()
            if now - last_inventory >= self.settings.inventory_interval:
                try:
                    self.send_inventory()
                    last_inventory = now
                    logger.info("Inventory uploaded successfully")
                except httpx.HTTPError as exc:
                    logger.error("Inventory upload failed: %s", exc)

            time.sleep(self.settings.heartbeat_interval)

    def close(self) -> None:
        if self._client:
            self._client.close()


def main() -> int:
    agent = VulnShieldAgent()
    try:
        if len(sys.argv) > 1:
            command = sys.argv[1]
            if command == "register":
                print(agent.register())
                return 0
            if command == "inventory":
                print(agent.send_inventory())
                return 0
            if command == "collect":
                import json

                print(json.dumps(collect_all(), indent=2))
                return 0
            logger.error("Unknown command: %s", command)
            return 1

        logger.info(
            "Starting VulnShield Linux Agent %s (id=%s)",
            agent.settings.version,
            agent.agent_id,
        )
        agent.run()
    except KeyboardInterrupt:
        logger.info("Agent stopped")
    finally:
        agent.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
