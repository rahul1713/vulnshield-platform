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
    return AgentSettings()
