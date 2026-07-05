"""VulnShield Reporting Service."""
from contextlib import asynccontextmanager
import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import make_asgi_app
from vulnshield_common.config import get_settings
from app.routes import reports

logger = structlog.get_logger()
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("service_starting", service="reporting-service")
    yield
    logger.info("service_stopping", service="reporting-service")


app = FastAPI(
    title="VulnShield Reporting Service",
    description="PDF, Excel, CSV, and JSON report generation",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.include_router(reports.router, prefix="/api/v1")
app.mount("/metrics", make_asgi_app())


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "healthy", "service": "VulnShield Reporting Service", "port": 8009}


@app.get("/", tags=["Health"])
async def root():
    return {"service": "VulnShield Reporting Service", "docs": "/docs"}
