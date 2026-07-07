"""VulnShield Notification Service."""
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI

from vulnshield_common.config import get_settings
from vulnshield_common.fastapi_setup import apply_service_middleware, service_openapi_kwargs

from app.routes import notifications

logger = structlog.get_logger()
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("service_starting", service="notification-service", environment=settings.environment)
    yield
    logger.info("service_stopping", service="notification-service")


app = FastAPI(
    title="VulnShield Notification Service",
    description="Email, Slack, and Teams notifications",
    version="1.0.0",
    lifespan=lifespan,
    **service_openapi_kwargs(settings),
)

apply_service_middleware(app, settings)

app.include_router(notifications.router, prefix="/api/v1")


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "healthy", "service": "VulnShield Notification Service", "port": 8011}


@app.get("/", tags=["Health"])
async def root():
    return {"service": "VulnShield Notification Service"}
