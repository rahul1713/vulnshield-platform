"""Production and sandbox security validation and middleware helpers."""

from __future__ import annotations

import os
import sys

from vulnshield_common.config import Settings

# Known weak defaults that must never be used outside local development.
_WEAK_SECRETS = frozenset({
    "change-me-jwt-secret-key-min-32-chars",
    "change-me-in-production",
    "change-me-in-production-use-openssl-rand-hex-32",
    "vulnshield_secure_password",
    "vulnshield_rabbit_password",
    "vulnshield_minio_secret",
    "vulnshield_minio",
    "change-me-minio-secret",
    "Admin@123456",
})

_PROTECTED_ENVIRONMENTS = frozenset({"production", "sandbox"})


def is_protected_environment(environment: str | None = None) -> bool:
    env = (environment or os.getenv("ENVIRONMENT", "development")).lower()
    return env in _PROTECTED_ENVIRONMENTS


def validate_production_settings(settings: Settings) -> None:
    """Fail fast when required secrets are missing or weak in sandbox/production."""
    if not is_protected_environment(settings.environment):
        return

    errors: list[str] = []

    if len(settings.jwt_secret) < 32:
        errors.append("JWT_SECRET must be at least 32 characters in sandbox/production.")
    if settings.jwt_secret in _WEAK_SECRETS:
        errors.append("JWT_SECRET is a known weak default; generate a unique secret.")

    if settings.postgres_password in _WEAK_SECRETS or len(settings.postgres_password) < 16:
        errors.append("POSTGRES_PASSWORD must be a strong unique value (min 16 chars).")

    if settings.rabbitmq_password in _WEAK_SECRETS or len(settings.rabbitmq_password) < 16:
        errors.append("RABBITMQ_PASSWORD must be a strong unique value (min 16 chars).")

    if settings.minio_secret_key in _WEAK_SECRETS or len(settings.minio_secret_key) < 16:
        errors.append("MINIO_SECRET_KEY must be a strong unique value (min 16 chars).")

    if is_protected_environment(settings.environment) and not settings.redis_password:
        errors.append("REDIS_PASSWORD is required in sandbox/production.")

    if settings.cors_origins.strip() in ("", "*"):
        errors.append("CORS_ORIGINS must list explicit allowed origins (comma-separated), not '*'.")

    if errors:
        for err in errors:
            print(f"SECURITY CONFIG ERROR: {err}", file=sys.stderr)
        raise SystemExit(1)


def get_cors_middleware_kwargs(settings: Settings) -> dict:
    """Return CORSMiddleware kwargs appropriate for the environment."""
    origins = settings.cors_origins_list
    if is_protected_environment(settings.environment):
        return {
            "allow_origins": origins,
            "allow_credentials": True,
            "allow_methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            "allow_headers": ["Authorization", "Content-Type", "X-Request-ID"],
        }
    # Local development — still avoid wildcard+credentials (invalid CORS combo).
    if "*" in origins:
        return {
            "allow_origins": ["http://localhost:3000", "http://127.0.0.1:3000"],
            "allow_credentials": True,
            "allow_methods": ["*"],
            "allow_headers": ["*"],
        }
    return {
        "allow_origins": origins,
        "allow_credentials": True,
        "allow_methods": ["*"],
        "allow_headers": ["*"],
    }


def fastapi_docs_config(environment: str) -> dict:
    """Disable OpenAPI docs in sandbox/production."""
    if is_protected_environment(environment):
        return {"docs_url": None, "redoc_url": None, "openapi_url": None}
    return {"docs_url": "/docs", "redoc_url": "/redoc", "openapi_url": "/openapi.json"}


def should_expose_metrics(environment: str) -> bool:
    """Metrics endpoints are internal-only in protected environments."""
    return not is_protected_environment(environment)
