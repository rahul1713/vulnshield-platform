"""VulnShield Web Scanner Service."""
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI

from vulnshield_common.config import get_settings
from vulnshield_common.fastapi_setup import apply_service_middleware, service_openapi_kwargs

from app.routes import web_scans

logger = structlog.get_logger()
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("service_starting", service="web-scanner-service", environment=settings.environment)
    yield
    logger.info("service_stopping", service="web-scanner-service")


app = FastAPI(
    title="VulnShield Web Scanner Service",
    description="DAST web application security scanning",
    version="1.0.0",
    lifespan=lifespan,
    **service_openapi_kwargs(settings),
)

apply_service_middleware(app, settings)

app.include_router(web_scans.router, prefix="/api/v1")


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "healthy", "service": "VulnShield Web Scanner Service", "port": 8004}


@app.get("/", tags=["Health"])
async def root():
    return {"service": "VulnShield Web Scanner Service"}
