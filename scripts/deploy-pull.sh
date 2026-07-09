#!/usr/bin/env bash
# Deploy VulnShield using pre-built images from GitHub Container Registry (no compile on laptop).
set -euo pipefail

export VULNSHIELD_USE_REGISTRY=1
export VULNSHIELD_REGISTRY="${VULNSHIELD_REGISTRY:-ghcr.io/rahul1713/vulnshield}"
export VULNSHIELD_TAG="${VULNSHIELD_TAG:-latest}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

echo "=== VulnShield Registry Deploy ==="
echo "Registry: ${VULNSHIELD_REGISTRY}-*:${VULNSHIELD_TAG}"
echo ""

if ! docker info >/dev/null 2>&1; then
  echo "Docker is not running. Start Docker Desktop and retry." >&2
  exit 1
fi

# Public GHCR images need no login; private org packages require a PAT.
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
  echo "${GITHUB_TOKEN}" | docker login ghcr.io -u "${GITHUB_USER:-$(whoami)}" --password-stdin 2>/dev/null || true
fi

chmod +x scripts/deploy.sh scripts/ensure-admin-password.sh scripts/wait-healthy.sh
./scripts/deploy.sh
