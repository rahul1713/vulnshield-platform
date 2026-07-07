"""VulnShield Reporting Service."""
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI

from vulnshield_common.config import get_settings
from vulnshield_common.fastapi_setup import apply_service_middleware, service_openapi_kwargs

from app.routes import reports

logger = structlog.get_logger()
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("service_starting", service="reporting-service", environment=settings.environment)
    yield
    logger.info("service_stopping", service="reporting-service")


app = FastAPI(
    title="VulnShield Reporting Service",
    description="Report generation and export",
    version="1.0.0",
    lifespan=lifespan,
    **service_openapi_kwargs(settings),
)

apply_service_middleware(app, settings)

app.include_router(reports.router, prefix="/api/v1")


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "healthy", "service": "VulnShield Reporting Service", "port": 8009}


@app.get("/", tags=["Health"])
async def root():
    return {"service": "VulnShield Reporting Service"}
