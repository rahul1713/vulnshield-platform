"""VulnShield Linux Agent configuration."""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class AgentSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file="/etc/vulnshield/agent.env",
        env_prefix="VULNSHIELD_",
        extra="ignore",
    )

    agent_id: str = ""
    api_url: str = "https://localhost:8080/api/v1"
    api_token: str = ""
    agent_token: str = ""
    heartbeat_interval: int = 300
    inventory_interval: int = 3600
    verify_ssl: bool = True
    mtls_enabled: bool = False
    client_cert: Path = Path("/etc/vulnshield/certs/client.crt")
    client_key: Path = Path("/etc/vulnshield/certs/client.key")
    ca_cert: Path = Path("/etc/vulnshield/certs/ca.crt")
    log_level: str = "INFO"
    platform: str = "linux"
    version: str = "1.0.0"


@lru_cache
def get_settings() -> AgentSettings:
    settings = AgentSettings()
    # AGENT_TOKEN (no prefix) for machine-scoped auth in sandbox/production.
    import os

    if not settings.agent_token:
        settings.agent_token = os.getenv("AGENT_TOKEN", "")
    if settings.agent_token and not settings.api_token:
        settings.api_token = settings.agent_token
    return settings
