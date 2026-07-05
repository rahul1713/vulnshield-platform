"""VulnShield Patch Intelligence Service."""
from contextlib import asynccontextmanager
import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import make_asgi_app
from vulnshield_common.config import get_settings
from app.routes import patches

logger = structlog.get_logger()
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("service_starting", service="patch-intelligence")
    yield
    logger.info("service_stopping", service="patch-intelligence")


app = FastAPI(
    title="VulnShield Patch Intelligence Service",
    description="Patch availability, vendor advisories, and EOL status",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.include_router(patches.router, prefix="/api/v1")
app.mount("/metrics", make_asgi_app())


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "healthy", "service": "VulnShield Patch Intelligence Service", "port": 8007}


@app.get("/", tags=["Health"])
async def root():
    return {"service": "VulnShield Patch Intelligence Service", "docs": "/docs"}
