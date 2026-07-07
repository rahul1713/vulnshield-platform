"""VulnShield Risk Engine."""
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI

from vulnshield_common.config import get_settings
from vulnshield_common.fastapi_setup import apply_service_middleware, service_openapi_kwargs

from app.routes import risk

logger = structlog.get_logger()
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("service_starting", service="risk-engine", environment=settings.environment)
    yield
    logger.info("service_stopping", service="risk-engine")


app = FastAPI(
    title="VulnShield Risk Engine",
    description="Risk scoring and prioritization",
    version="1.0.0",
    lifespan=lifespan,
    **service_openapi_kwargs(settings),
)

apply_service_middleware(app, settings)

app.include_router(risk.router, prefix="/api/v1")


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "healthy", "service": "VulnShield Risk Engine", "port": 8008}


@app.get("/", tags=["Health"])
async def root():
    return {"service": "VulnShield Risk Engine"}
