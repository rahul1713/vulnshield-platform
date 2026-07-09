#!/usr/bin/env bash
# Wait for VulnShield sandbox API and frontend to become healthy.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="${1:-${ROOT}/.env.sandbox}"
API_PORT="${API_PORT:-18080}"
FRONTEND_PORT="${FRONTEND_PORT:-3002}"
MAX_WAIT="${MAX_WAIT:-180}"

echo "Waiting for VulnShield (up to ${MAX_WAIT}s)..."

for i in $(seq 1 "${MAX_WAIT}"); do
  if curl -sf "http://127.0.0.1:${API_PORT}/health" >/dev/null 2>&1 \
    && curl -sf "http://127.0.0.1:${FRONTEND_PORT}" >/dev/null 2>&1; then
    echo "VulnShield is ready."
    exit 0
  fi
  sleep 1
done

echo "Timed out waiting for VulnShield health." >&2
exit 1
