"""VulnShield Compliance Service."""
from contextlib import asynccontextmanager
import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import make_asgi_app
from vulnshield_common.config import get_settings
from app.routes import compliance

logger = structlog.get_logger()
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("service_starting", service="compliance-service")
    yield
    logger.info("service_stopping", service="compliance-service")


app = FastAPI(
    title="VulnShield Compliance Service",
    description="CIS/NIST/ISO/PCI mapping and CIS benchmark assessment",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.include_router(compliance.router, prefix="/api/v1")
app.mount("/metrics", make_asgi_app())


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "healthy", "service": "VulnShield Compliance Service", "port": 8010}


@app.get("/", tags=["Health"])
async def root():
    return {"service": "VulnShield Compliance Service", "docs": "/docs"}
