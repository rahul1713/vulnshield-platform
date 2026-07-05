"""VulnShield Windows Agent configuration."""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class AgentSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=r"C:\ProgramData\VulnShield\agent.env",
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
    client_cert: Path = Path(r"C:\ProgramData\VulnShield\certs\client.crt")
    client_key: Path = Path(r"C:\ProgramData\VulnShield\certs\client.key")
    ca_cert: Path = Path(r"C:\ProgramData\VulnShield\certs\ca.crt")
    log_level: str = "INFO"
    platform: str = "windows"
    version: str = "1.0.0"
    powershell_script: Path = Path(r"C:\Program Files\VulnShield\collectors.ps1")


@lru_cache
def get_settings() -> AgentSettings:
    return AgentSettings()
