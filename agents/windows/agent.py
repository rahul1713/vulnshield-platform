#!/usr/bin/env python3
"""VulnShield Windows Agent - PowerShell/Python hybrid inventory agent."""

from __future__ import annotations

import hashlib
import json
import logging
import socket
import ssl
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone

import httpx

from config import AgentSettings, get_settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("vulnshield-agent-windows")


class VulnShieldWindowsAgent:
    """Windows endpoint agent using PowerShell for collection."""

    def __init__(self, settings: AgentSettings | None = None):
        self.settings = settings or get_settings()
        logging.getLogger().setLevel(self.settings.log_level.upper())
        self.agent_id = self.settings.agent_id or self._generate_agent_id()
        self._client: httpx.Client | None = None

    def _generate_agent_id(self) -> str:
        hostname = socket.gethostname()
        raw = f"{hostname}:{uuid.getnode()}"
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    def _build_ssl_context(self) -> ssl.SSLContext | bool:
        if not self.settings.mtls_enabled:
            return self.settings.verify_ssl

        ctx = ssl.create_default_context(cafile=str(self.settings.ca_cert))
        ctx.load_cert_chain(
            certfile=str(self.settings.client_cert),
            keyfile=str(self.settings.client_key),
        )
        return ctx

    def _get_client(self) -> httpx.Client:
        if self._client is None:
            headers = {}
            if self.settings.api_token:
                headers["Authorization"] = f"Bearer {self.settings.api_token}"

            self._client = httpx.Client(
                base_url=self.settings.api_url.rstrip("/"),
                headers=headers,
                timeout=httpx.Timeout(120.0, connect=10.0),
                verify=self._build_ssl_context(),
            )
        return self._client

    def _post(self, path: str, payload: dict) -> httpx.Response:
        response = self._get_client().post(path, json=payload)
        response.raise_for_status()
        return response

    def collect_inventory(self) -> dict:
        """Invoke PowerShell collector script and parse JSON output."""
        script = self.settings.powershell_script
        if not script.exists():
            raise FileNotFoundError(f"Collector script not found: {script}")

        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script),
            ],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(f"PowerShell collector failed: {result.stderr}")

        return json.loads(result.stdout)

    def register(self) -> dict:
        payload = {
            "agent_id": self.agent_id,
            "hostname": socket.gethostname(),
            "platform": self.settings.platform,
            "version": self.settings.version,
            "metadata": {"registered_at": datetime.now(timezone.utc).isoformat()},
        }
        return self._post("/agents/register", payload).json()

    def heartbeat(self) -> dict:
        payload = {
            "agent_id": self.agent_id,
            "status": "online",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        return self._post(f"/agents/{self.agent_id}/heartbeat", payload).json()

    def send_inventory(self) -> dict:
        inventory = self.collect_inventory()
        payload = {
            "agent_id": self.agent_id,
            "platform": self.settings.platform,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "inventory": inventory,
        }
        return self._post(f"/agents/{self.agent_id}/inventory", payload).json()

    def run(self) -> None:
        try:
            self.register()
        except httpx.HTTPError as exc:
            logger.warning("Registration failed: %s", exc)

        last_inventory = 0.0
        while True:
            try:
                self.heartbeat()
            except httpx.HTTPError as exc:
                logger.error("Heartbeat failed: %s", exc)

            now = time.monotonic()
            if now - last_inventory >= self.settings.inventory_interval:
                try:
                    self.send_inventory()
                    last_inventory = now
                except (httpx.HTTPError, RuntimeError, json.JSONDecodeError) as exc:
                    logger.error("Inventory failed: %s", exc)

            time.sleep(self.settings.heartbeat_interval)

    def close(self) -> None:
        if self._client:
            self._client.close()


def main() -> int:
    agent = VulnShieldWindowsAgent()
    try:
        if len(sys.argv) > 1 and sys.argv[1] == "collect":
            print(json.dumps(agent.collect_inventory(), indent=2))
            return 0
        agent.run()
    except KeyboardInterrupt:
        pass
    finally:
        agent.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
