"""VulnShield Scanner Service."""
from contextlib import asynccontextmanager
import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import make_asgi_app
from vulnshield_common.config import get_settings
from app.routes import agents, dashboard, ingestion, scans, search, vulnerabilities

logger = structlog.get_logger()
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("service_starting", service="scanner-service")
    yield
    logger.info("service_stopping", service="scanner-service")


app = FastAPI(
    title="VulnShield Scanner Service",
    description="Agent ingestion, agentless scanning, CVE correlation, scan management",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.include_router(scans.router, prefix="/api/v1")
app.include_router(agents.router, prefix="/api/v1")
app.include_router(ingestion.router, prefix="/api/v1")
app.include_router(vulnerabilities.router, prefix="/api/v1")
app.include_router(dashboard.router, prefix="/api/v1")
app.include_router(search.router, prefix="/api/v1")
app.mount("/metrics", make_asgi_app())


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "healthy", "service": "VulnShield Scanner Service", "port": 8003}


@app.get("/", tags=["Health"])
async def root():
    return {"service": "VulnShield Scanner Service", "docs": "/docs"}
