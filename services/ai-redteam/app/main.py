"""VulnShield AI Red Team."""
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI

from vulnshield_common.config import get_settings
from vulnshield_common.fastapi_setup import apply_service_middleware, service_openapi_kwargs

from app.routes import campaigns

logger = structlog.get_logger()
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("service_starting", service="ai-redteam", environment=settings.environment)
    yield
    logger.info("service_stopping", service="ai-redteam")


app = FastAPI(
    title="VulnShield AI Red Team",
    description="Automated adversary simulation",
    version="1.0.0",
    lifespan=lifespan,
    **service_openapi_kwargs(settings),
)

apply_service_middleware(app, settings)

app.include_router(campaigns.router, prefix="/api/v1")


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "healthy", "service": "VulnShield AI Red Team", "port": 8006}


@app.get("/", tags=["Health"])
async def root():
    return {"service": "VulnShield AI Red Team"}
