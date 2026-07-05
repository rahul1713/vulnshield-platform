"""VulnShield Asset Service."""
from contextlib import asynccontextmanager
import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import make_asgi_app
from vulnshield_common.config import get_settings
from app.routes import assets
logger = structlog.get_logger()
settings = get_settings()

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("service_starting", service="asset-service")
    yield
    logger.info("service_stopping", service="asset-service")

app = FastAPI(title="VulnShield Asset Service", description="Asset CRUD, discovery, software inventory, ports, search, history", version="1.0.0", lifespan=lifespan,
    docs_url="/docs", redoc_url="/redoc", openapi_url="/openapi.json")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"])
app.include_router(assets.router, prefix="/api/v1")
app.mount("/metrics", make_asgi_app())

@app.get("/health", tags=["Health"])
async def health():
    return {"status": "healthy", "service": "VulnShield Asset Service", "port": 8002}

@app.get("/", tags=["Health"])
async def root():
    return {"service": "VulnShield Asset Service", "docs": "/docs"}
