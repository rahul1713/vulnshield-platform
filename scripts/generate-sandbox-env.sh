#!/usr/bin/env bash
# Generate a .env file with cryptographically random secrets for sandbox deployment.
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
INIT_ADMIN_PASSWORD="$(openssl rand -base64 24 | tr -d '/+=' | head -c 24)"

cat > "${ROOT}/${OUT}" <<EOF
# VulnShield Sandbox Environment — AUTO-GENERATED $(date -u +%Y-%m-%dT%H:%M:%SZ)
# NEVER commit this file. Store secrets in your vault / secret manager.

ENVIRONMENT=sandbox
LOG_LEVEL=INFO

# Bootstrap admin (shown once below — change after first login)
INIT_ADMIN_USERNAME=admin
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

# CORS — set to your sandbox frontend URL(s)
CORS_ORIGINS=http://localhost:3000,https://vulnshield-sandbox.example.com

# Security AI — local Ollama only
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://ollama:11434
OLLAMA_MODEL=qwen3.6
AI_SECURITY_LOCAL_ONLY=true
AI_SECURITY_ALLOWED_MODELS=qwen3.6

# Frontend (sandbox — demo mode OFF)
NEXT_PUBLIC_API_URL=http://localhost:8080/api/v1
NEXT_PUBLIC_DEPLOY_ENV=sandbox
NEXT_PUBLIC_ENABLE_DEMO_MODE=false

API_GATEWAY_PORT=8080
EOF

chmod 600 "${ROOT}/${OUT}"

echo "Wrote ${OUT}"
echo ""
echo "=== SAVE THESE CREDENTIALS SECURELY (shown once) ==="
echo "Admin username: admin"
echo "Admin password: ${INIT_ADMIN_PASSWORD}"
echo "===================================================="
echo ""
echo "Deploy with: docker compose --env-file ${OUT} -f docker-compose.yml -f docker-compose.sandbox.yml up -d"
