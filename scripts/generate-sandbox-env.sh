#!/usr/bin/env bash
# Generate a .env file with secrets for sandbox / organization deployment.
# Usage: ./scripts/generate-sandbox-env.sh [output-file]
set -euo pipefail

OUT="${1:-.env.sandbox}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

rand_hex() { openssl rand -hex "$1"; }

POSTGRES_PASSWORD="$(rand_hex 24)"
RABBITMQ_PASSWORD="$(rand_hex 24)"
MINIO_SECRET_KEY="$(rand_hex 24)"
REDIS_PASSWORD="$(rand_hex 24)"
JWT_SECRET="$(rand_hex 32)"

# Organization default — same for every fresh deploy; change before external sharing.
INIT_ADMIN_PASSWORD="${INIT_ADMIN_PASSWORD:-Admin@123456}"
INIT_ADMIN_USERNAME="${INIT_ADMIN_USERNAME:-admin}"

cat > "${ROOT}/${OUT}" <<EOF
# VulnShield Organization Sandbox — AUTO-GENERATED $(date -u +%Y-%m-%dT%H:%M:%SZ)
# NEVER commit this file.

ENVIRONMENT=sandbox
LOG_LEVEL=INFO

# Organization login (dashboard)
INIT_ADMIN_USERNAME=${INIT_ADMIN_USERNAME}
INIT_ADMIN_EMAIL=admin@vulnshield.local
INIT_ADMIN_PASSWORD=${INIT_ADMIN_PASSWORD}

JWT_SECRET=${JWT_SECRET}
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7

POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_DB=vulnshield
POSTGRES_USER=vulnshield
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}

REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=${REDIS_PASSWORD}

RABBITMQ_HOST=rabbitmq
RABBITMQ_PORT=5672
RABBITMQ_USER=vulnshield
RABBITMQ_PASSWORD=${RABBITMQ_PASSWORD}
RABBITMQ_VHOST=vulnshield

MINIO_ENDPOINT=minio:9000
MINIO_ACCESS_KEY=vulnshield_minio_$(rand_hex 4)
MINIO_SECRET_KEY=${MINIO_SECRET_KEY}
MINIO_BUCKET=vulnshield-evidence
MINIO_USE_SSL=false

CORS_ORIGINS=http://localhost:3002,http://127.0.0.1:3002

LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://ollama:11434
OLLAMA_MODEL=qwen3.6
AI_SECURITY_LOCAL_ONLY=true
AI_SECURITY_ALLOWED_MODELS=qwen3.6

SCAN_SANDBOX_MODE=true
ALLOW_SIMULATED_SCANS=false
ALLOW_EXTERNAL_TARGETS=false
SANDBOX_ALLOW_PRIVATE=false
CVE_SYNC_ON_STARTUP=true

NEXT_PUBLIC_API_URL=http://127.0.0.1:18080/api/v1
NEXT_PUBLIC_API_PORT=18080
NEXT_PUBLIC_DEPLOY_ENV=sandbox
NEXT_PUBLIC_ENABLE_DEMO_MODE=false

FRONTEND_PORT=3002
API_GATEWAY_PORT=18080
EOF

chmod 600 "${ROOT}/${OUT}"

echo "Wrote ${OUT}"
echo ""
echo "Organization login:"
echo "  URL:      http://127.0.0.1:3002"
echo "  Username: ${INIT_ADMIN_USERNAME}"
echo "  Password: ${INIT_ADMIN_PASSWORD}"
echo ""
echo "Deploy with: make deploy"
