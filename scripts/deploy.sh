#!/usr/bin/env bash
# One-command organization deployment for VulnShield sandbox.
# Usage: ./scripts/deploy.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

ENV_FILE="${ROOT}/.env.sandbox"
FRONTEND_PORT=3002
API_PORT=18080

echo "=== VulnShield Organization Deploy ==="

# Docker Desktop VM can run out of disk even when the host has free space.
if ! docker info >/dev/null 2>&1; then
  echo "Docker is not running. Start Docker Desktop and retry." >&2
  exit 1
fi

if docker run --rm alpine df -h /var/lib/docker 2>/dev/null | grep -q '100%'; then
  echo "WARNING: Docker disk may be full. In Docker Desktop: Settings → Resources → increase disk," >&2
  echo "or run: docker builder prune -f" >&2
fi

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "Creating ${ENV_FILE} ..."
  "${ROOT}/scripts/generate-sandbox-env.sh" "${ENV_FILE}"
else
  echo "Using existing ${ENV_FILE}"
fi

COMPOSE_FILES=(-f docker-compose.yml -f docker-compose.sandbox.yml)
UP_EXTRA=()

if [[ "${VULNSHIELD_USE_REGISTRY:-}" == "1" ]]; then
  COMPOSE_FILES+=(-f docker-compose.registry.yml)
  echo "Using pre-built images from ${VULNSHIELD_REGISTRY:-ghcr.io/rahul1713/vulnshield}:${VULNSHIELD_TAG:-latest}"
  UP_EXTRA+=(--pull always)
else
  echo "Building images locally (first run may take 10–20 minutes)..."
  UP_EXTRA+=(--build)
fi

echo "Starting all services..."
docker compose --env-file "${ENV_FILE}" "${COMPOSE_FILES[@]}" \
  --profile ai --profile scan up -d "${UP_EXTRA[@]}"

echo "Running database migrations..."
docker compose --env-file "${ENV_FILE}" "${COMPOSE_FILES[@]}" \
  exec -T postgres psql -U vulnshield -d vulnshield -f /migrations/003_simulated_flags.sql >/dev/null 2>&1 || true
docker compose --env-file "${ENV_FILE}" "${COMPOSE_FILES[@]}" \
  exec -T postgres psql -U vulnshield -d vulnshield -f /migrations/004_agent_tokens.sql >/dev/null 2>&1 || true

echo "Synchronizing admin credentials..."
INIT_ADMIN_PASSWORD="$(grep '^INIT_ADMIN_PASSWORD=' "${ENV_FILE}" | cut -d= -f2-)"
export INIT_ADMIN_PASSWORD
export INIT_ADMIN_USERNAME="$(grep '^INIT_ADMIN_USERNAME=' "${ENV_FILE}" | cut -d= -f2- || echo admin)"
export INIT_ADMIN_EMAIL="$(grep '^INIT_ADMIN_EMAIL=' "${ENV_FILE}" | cut -d= -f2- || echo admin@vulnshield.local)"
"${ROOT}/scripts/ensure-admin-password.sh" "${ENV_FILE}"

echo "Pulling AI model (qwen3.6) if needed..."
docker compose --env-file "${ENV_FILE}" "${COMPOSE_FILES[@]}" \
  --profile ai run --rm ollama-init || true

API_PORT="${API_PORT}" FRONTEND_PORT="${FRONTEND_PORT}" "${ROOT}/scripts/wait-healthy.sh" "${ENV_FILE}"

ADMIN_USER="$(grep '^INIT_ADMIN_USERNAME=' "${ENV_FILE}" | cut -d= -f2- || echo admin)"

cat <<EOF

╔══════════════════════════════════════════════════════════════╗
║           VulnShield is ready for your organization          ║
╠══════════════════════════════════════════════════════════════╣
║  Open dashboard:  http://127.0.0.1:${FRONTEND_PORT}                    ║
║  API health:      http://127.0.0.1:${API_PORT}/health                ║
║                                                              ║
║  Login username:  ${ADMIN_USER}                                      ║
║  Login password:  ${INIT_ADMIN_PASSWORD}                          ║
╚══════════════════════════════════════════════════════════════╝

Stop: make sandbox-down

EOF
