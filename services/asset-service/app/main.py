"""VulnShield Asset Service."""
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI

from vulnshield_common.config import get_settings
from vulnshield_common.fastapi_setup import apply_service_middleware, service_openapi_kwargs

from app.routes import assets

logger = structlog.get_logger()
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("service_starting", service="asset-service", environment=settings.environment)
    yield
    logger.info("service_stopping", service="asset-service")


app = FastAPI(
    title="VulnShield Asset Service",
    description="Asset CRUD, discovery, software inventory, ports, search, history",
    version="1.0.0",
    lifespan=lifespan,
    **service_openapi_kwargs(settings),
)

apply_service_middleware(app, settings)

app.include_router(assets.router, prefix="/api/v1")


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "healthy", "service": "VulnShield Asset Service", "port": 8002}


@app.get("/", tags=["Health"])
async def root():
    return {"service": "VulnShield Asset Service"}
