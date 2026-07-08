"""VulnShield Scan Worker — real security scan execution via RabbitMQ."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI

from vulnshield_common.config import get_settings
from vulnshield_common.fastapi_setup import apply_service_middleware, service_openapi_kwargs

from app.consumer import start_consumer

logger = structlog.get_logger()
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("service_starting", service="scan-worker", environment=settings.environment)
    consumer_task = asyncio.create_task(start_consumer())
    yield
    consumer_task.cancel()
    try:
        await consumer_task
    except asyncio.CancelledError:
        pass
    logger.info("service_stopping", service="scan-worker")


app = FastAPI(
    title="VulnShield Scan Worker",
    description="Background worker executing real security scans (nmap, nuclei, semgrep, ZAP)",
    version="1.0.0",
    lifespan=lifespan,
    **service_openapi_kwargs(settings),
)

apply_service_middleware(app, settings)


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "healthy", "service": "VulnShield Scan Worker", "port": 8012}


@app.get("/", tags=["Health"])
async def root():
    return {"service": "VulnShield Scan Worker"}
