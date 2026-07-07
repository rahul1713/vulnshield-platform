"""VulnShield Scanner Service."""
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI

from vulnshield_common.config import get_settings
from vulnshield_common.fastapi_setup import apply_service_middleware, service_openapi_kwargs

from app.routes import agents, dashboard, ingestion, scans, search, vulnerabilities

logger = structlog.get_logger()
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("service_starting", service="scanner-service", environment=settings.environment)
    yield
    logger.info("service_stopping", service="scanner-service")


app = FastAPI(
    title="VulnShield Scanner Service",
    description="Agent ingestion, agentless scanning, CVE correlation, scan management",
    version="1.0.0",
    lifespan=lifespan,
    **service_openapi_kwargs(settings),
)

apply_service_middleware(app, settings)

app.include_router(scans.router, prefix="/api/v1")
app.include_router(agents.router, prefix="/api/v1")
app.include_router(ingestion.router, prefix="/api/v1")
app.include_router(vulnerabilities.router, prefix="/api/v1")
app.include_router(dashboard.router, prefix="/api/v1")
app.include_router(search.router, prefix="/api/v1")


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "healthy", "service": "VulnShield Scanner Service", "port": 8003}


@app.get("/", tags=["Health"])
async def root():
    return {"service": "VulnShield Scanner Service"}
