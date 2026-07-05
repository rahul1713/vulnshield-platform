from abc import ABC, abstractmethod
from typing import Any
from urllib.parse import urlparse

import httpx
import structlog

from vulnshield_common.config import get_settings

logger = structlog.get_logger()
settings = get_settings()

LOCAL_OLLAMA_HOSTS = {"localhost", "127.0.0.1", "ollama", "::1"}


class SecurityLLMConfigurationError(RuntimeError):
    """Raised when security AI is configured to use a non-local or disallowed model."""


class LLMProvider(ABC):
    @abstractmethod
    async def generate(self, system_prompt: str, user_prompt: str, temperature: float = 0.1) -> str:
        pass

    @abstractmethod
    async def generate_json(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        pass


class OllamaProvider(LLMProvider):
    def __init__(self, base_url: str | None = None, model: str | None = None):
        self.base_url = base_url or settings.ollama_base_url
        self.model = model or settings.ollama_model

    async def generate(self, system_prompt: str, user_prompt: str, temperature: float = 0.1) -> str:
        async with httpx.AsyncClient(timeout=300.0) as client:
            response = await client.post(
                f"{self.base_url.rstrip('/')}/api/chat",
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    "stream": False,
                    "options": {"temperature": temperature},
                },
            )
            response.raise_for_status()
            return response.json()["message"]["content"]

    async def generate_json(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        import json

        content = await self.generate(
            system_prompt + "\nRespond ONLY with valid JSON.",
            user_prompt,
        )
        try:
            start = content.find("{")
            end = content.rfind("}") + 1
            if start >= 0 and end > start:
                return json.loads(content[start:end])
            start = content.find("[")
            end = content.rfind("]") + 1
            if start >= 0 and end > start:
                return {"findings": json.loads(content[start:end])}
        except json.JSONDecodeError:
            pass
        return {"raw_response": content}


def _is_local_ollama_url(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return host in LOCAL_OLLAMA_HOSTS


def _model_is_allowed(model: str, allowed_prefixes: list[str]) -> bool:
    normalized = model.lower().strip()
    return any(normalized == prefix or normalized.startswith(f"{prefix}:") for prefix in allowed_prefixes)


def get_local_security_llm_provider() -> LLMProvider:
    """Return Ollama provider for security AI workloads (local Qwen 3.6 only)."""
    if settings.llm_provider.lower() != "ollama":
        raise SecurityLLMConfigurationError(
            "Security AI features (vulnerability scanning, code review, red teaming) require "
            f"LLM_PROVIDER=ollama. Cloud providers are not permitted (configured: {settings.llm_provider})."
        )
    if not _is_local_ollama_url(settings.ollama_base_url):
        raise SecurityLLMConfigurationError(
            "Security AI requires a local Ollama instance. "
            f"OLLAMA_BASE_URL must point to localhost or the ollama service (configured: {settings.ollama_base_url})."
        )
    allowed = [m.strip().lower() for m in settings.ai_security_allowed_models.split(",") if m.strip()]
    if allowed and not _model_is_allowed(settings.ollama_model, allowed):
        raise SecurityLLMConfigurationError(
            "Security AI requires a Qwen 3.6 model via Ollama. "
            f"Set OLLAMA_MODEL to qwen3.6 (or a qwen3.6:* variant). Configured: {settings.ollama_model}."
        )
    logger.info(
        "security_llm_provider",
        provider="ollama",
        model=settings.ollama_model,
        base_url=settings.ollama_base_url,
    )
    return OllamaProvider()


def get_llm_provider() -> LLMProvider:
    """General-purpose LLM provider (non-security workloads only)."""
    if settings.ai_security_local_only:
        return get_local_security_llm_provider()
    return OllamaProvider()
