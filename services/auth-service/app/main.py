"""Auth Service - VulnShield Platform."""
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI

from vulnshield_common.config import get_settings
from vulnshield_common.fastapi_setup import apply_service_middleware, service_openapi_kwargs

from app.bootstrap import ensure_bootstrap_admin
from app.routes import audit, auth, roles, users

logger = structlog.get_logger()
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("service_starting", service="auth-service", environment=settings.environment)
    await ensure_bootstrap_admin()
    yield
    logger.info("service_stopping", service="auth-service")


app = FastAPI(
    title="VulnShield Auth Service",
    description="JWT authentication, user CRUD, RBAC, audit logging, and MFA",
    version="1.0.0",
    lifespan=lifespan,
    **service_openapi_kwargs(settings),
)

apply_service_middleware(app, settings)

app.include_router(auth.router, prefix="/api/v1")
app.include_router(users.router, prefix="/api/v1")
app.include_router(roles.router, prefix="/api/v1")
app.include_router(audit.router, prefix="/api/v1")


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "healthy", "service": "VulnShield Auth Service", "port": 8001}


@app.get("/", tags=["Health"])
async def root():
    return {"service": "VulnShield Auth Service"}
