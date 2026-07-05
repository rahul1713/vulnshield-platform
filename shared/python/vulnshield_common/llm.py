from abc import ABC, abstractmethod
from typing import Any

import httpx
import structlog

from vulnshield_common.config import get_settings

logger = structlog.get_logger()
settings = get_settings()


class LLMProvider(ABC):
    @abstractmethod
    async def generate(self, system_prompt: str, user_prompt: str, temperature: float = 0.1) -> str:
        pass

    @abstractmethod
    async def generate_json(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        pass


class OllamaProvider(LLMProvider):
    def __init__(self):
        self.base_url = settings.ollama_base_url
        self.model = settings.ollama_model

    async def generate(self, system_prompt: str, user_prompt: str, temperature: float = 0.1) -> str:
        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(
                f"{self.base_url}/api/chat",
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
            return json.loads(content[start:end])
        except json.JSONDecodeError:
            return {"raw_response": content}


class OpenAIProvider(LLMProvider):
    def __init__(self):
        self.api_key = settings.openai_api_key
        self.model = settings.openai_model

    async def generate(self, system_prompt: str, user_prompt: str, temperature: float = 0.1) -> str:
        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    "temperature": temperature,
                },
            )
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"]

    async def generate_json(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        import json
        content = await self.generate(
            system_prompt + "\nRespond ONLY with valid JSON.",
            user_prompt,
        )
        start = content.find("{")
        end = content.rfind("}") + 1
        return json.loads(content[start:end])


class AnthropicProvider(LLMProvider):
    def __init__(self):
        self.api_key = settings.anthropic_api_key
        self.model = settings.anthropic_model

    async def generate(self, system_prompt: str, user_prompt: str, temperature: float = 0.1) -> str:
        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": self.model,
                    "max_tokens": 4096,
                    "system": system_prompt,
                    "messages": [{"role": "user", "content": user_prompt}],
                    "temperature": temperature,
                },
            )
            response.raise_for_status()
            return response.json()["content"][0]["text"]

    async def generate_json(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        import json
        content = await self.generate(
            system_prompt + "\nRespond ONLY with valid JSON.",
            user_prompt,
        )
        start = content.find("{")
        end = content.rfind("}") + 1
        return json.loads(content[start:end])


class AzureOpenAIProvider(LLMProvider):
    def __init__(self):
        self.endpoint = settings.azure_openai_endpoint
        self.api_key = settings.azure_openai_api_key
        self.deployment = settings.azure_openai_deployment

    async def generate(self, system_prompt: str, user_prompt: str, temperature: float = 0.1) -> str:
        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(
                f"{self.endpoint}/openai/deployments/{self.deployment}/chat/completions?api-version=2024-02-01",
                headers={"api-key": self.api_key},
                json={
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    "temperature": temperature,
                },
            )
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"]

    async def generate_json(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        import json
        content = await self.generate(
            system_prompt + "\nRespond ONLY with valid JSON.",
            user_prompt,
        )
        start = content.find("{")
        end = content.rfind("}") + 1
        return json.loads(content[start:end])


def get_llm_provider() -> LLMProvider:
    providers = {
        "ollama": OllamaProvider,
        "openai": OpenAIProvider,
        "anthropic": AnthropicProvider,
        "azure_openai": AzureOpenAIProvider,
    }
    provider_class = providers.get(settings.llm_provider, OllamaProvider)
    return provider_class()
