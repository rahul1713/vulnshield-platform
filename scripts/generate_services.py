#!/usr/bin/env python3
"""Generate VulnShield Platform microservices."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVICES = ROOT / "services"

COMMON_REQS = """vulnshield-common
structlog>=24.1.0
"""

def write(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.strip() + "\n")

def dockerfile(service: str, port: int) -> str:
    return f"""FROM python:3.11-slim
WORKDIR /app
COPY shared/python /shared/python
RUN pip install --no-cache-dir /shared/python
COPY services/{service}/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY services/{service}/app /app/app
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "{port}"]
"""

def main_py(title: str, desc: str, routes: list[str], port: int) -> str:
    imports = "\n".join(f"from app.routes import {r}" for r in routes)
    includes = "\n".join(f'app.include_router({r}.router, prefix="/api/v1")' for r in routes)
    return f'''"""{title} - VulnShield Platform."""
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import make_asgi_app

from vulnshield_common.config import get_settings

{imports}

logger = structlog.get_logger()
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("service_starting", service="{title.lower().replace(" ", "-")}", environment=settings.environment)
    yield
    logger.info("service_stopping", service="{title.lower().replace(" ", "-")}")


app = FastAPI(
    title="{title}",
    description="{desc}",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

{includes}

metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)


@app.get("/health", tags=["Health"])
async def health():
    return {{"status": "healthy", "service": "{title}", "port": {port}}}


@app.get("/", tags=["Health"])
async def root():
    return {{"service": "{title}", "docs": "/docs", "health": "/health"}}
'''

def conftest() -> str:
    return '''"""Shared test fixtures."""
import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
'''

def test_health(service_name: str) -> str:
    return f'''"""Health endpoint tests."""
import pytest


@pytest.mark.asyncio
async def test_health(client):
    response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "{service_name}"


@pytest.mark.asyncio
async def test_root(client):
    response = await client.get("/")
    assert response.status_code == 200
    assert "docs" in response.json()
'''

if __name__ == "__main__":
    print("Use individual file writes")
