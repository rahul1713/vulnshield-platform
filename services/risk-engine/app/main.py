"""VulnShield Risk Engine Service."""
from contextlib import asynccontextmanager
import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import make_asgi_app
from vulnshield_common.config import get_settings
from app.routes import risk

logger = structlog.get_logger()
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("service_starting", service="risk-engine")
    yield
    logger.info("service_stopping", service="risk-engine")


app = FastAPI(
    title="VulnShield Risk Engine Service",
    description="Technical and business risk scoring with CVSS, EPSS, and asset criticality",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.include_router(risk.router, prefix="/api/v1")
app.mount("/metrics", make_asgi_app())


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "healthy", "service": "VulnShield Risk Engine Service", "port": 8008}


@app.get("/", tags=["Health"])
async def root():
    return {"service": "VulnShield Risk Engine Service", "docs": "/docs"}
