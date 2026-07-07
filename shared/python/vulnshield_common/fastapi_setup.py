"""Shared FastAPI application setup for all VulnShield microservices."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import make_asgi_app

from vulnshield_common.config import Settings, get_settings
from vulnshield_common.security import (
    fastapi_docs_config,
    get_cors_middleware_kwargs,
    should_expose_metrics,
    validate_production_settings,
)


def apply_service_middleware(app: FastAPI, settings: Settings | None = None) -> None:
    """Apply CORS, validate secrets, and optionally mount Prometheus metrics."""
    cfg = settings or get_settings()
    validate_production_settings(cfg)
    app.add_middleware(CORSMiddleware, **get_cors_middleware_kwargs(cfg))
    if should_expose_metrics(cfg.environment):
        app.mount("/metrics", make_asgi_app())


def service_openapi_kwargs(settings: Settings | None = None) -> dict:
    cfg = settings or get_settings()
    return fastapi_docs_config(cfg.environment)
