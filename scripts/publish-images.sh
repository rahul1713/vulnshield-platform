#!/usr/bin/env bash
# Build and push all VulnShield images to GitHub Container Registry.
# Requires: docker, gh auth login (or GITHUB_TOKEN with write:packages)
#
# Usage:
#   ./scripts/publish-images.sh [tag]
#   ./scripts/publish-images.sh v1.0.0
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

TAG="${1:-latest}"
REGISTRY="${VULNSHIELD_REGISTRY:-ghcr.io/rahul1713/vulnshield}"
OWNER="${GITHUB_REPOSITORY_OWNER:-rahul1713}"

echo "=== Publishing VulnShield images ==="
echo "Registry: ${REGISTRY}-*:${TAG}"
echo ""

if ! docker info >/dev/null 2>&1; then
  echo "Docker is not running." >&2
  exit 1
fi

if [[ -z "${GITHUB_TOKEN:-}" ]]; then
  if command -v gh >/dev/null 2>&1; then
    GITHUB_TOKEN="$(gh auth token 2>/dev/null || true)"
  fi
fi

if [[ -z "${GITHUB_TOKEN:-}" ]]; then
  echo "Set GITHUB_TOKEN or run: gh auth login" >&2
  exit 1
fi

echo "${GITHUB_TOKEN}" | docker login ghcr.io -u "${OWNER}" --password-stdin

build_push() {
  local service="$1"
  local context="$2"
  local dockerfile="$3"
  shift 3
  local -a extra_args=("$@")
  local image="${REGISTRY}-${service}:${TAG}"

  echo "--- Building ${image} ---"
  docker build -t "${image}" -f "${dockerfile}" "${extra_args[@]}" "${context}"
  docker tag "${image}" "${REGISTRY}-${service}:latest"
  docker push "${image}"
  docker push "${REGISTRY}-${service}:latest"
}

# Sandbox frontend (baked for org deploy ports)
build_push frontend frontend frontend/Dockerfile \
  --build-arg "NEXT_PUBLIC_API_URL=http://127.0.0.1:18080/api/v1" \
  --build-arg "NEXT_PUBLIC_API_PORT=18080" \
  --build-arg "NEXT_PUBLIC_DEPLOY_ENV=sandbox" \
  --build-arg "NEXT_PUBLIC_ENABLE_DEMO_MODE=false"

build_push api-gateway services/api-gateway services/api-gateway/Dockerfile
build_push auth-service . services/auth-service/Dockerfile
build_push asset-service . services/asset-service/Dockerfile
build_push scanner-service . services/scanner-service/Dockerfile
build_push web-scanner-service . services/web-scanner-service/Dockerfile
build_push scan-worker . services/scan-worker/Dockerfile
build_push ai-code-review . services/ai-code-review/Dockerfile
build_push ai-redteam . services/ai-redteam/Dockerfile
build_push patch-intelligence . services/patch-intelligence/Dockerfile
build_push risk-engine . services/risk-engine/Dockerfile
build_push reporting-service . services/reporting-service/Dockerfile
build_push compliance-service . services/compliance-service/Dockerfile
build_push notification-service . services/notification-service/Dockerfile

cat <<EOF

Published to GitHub Container Registry:
  ${REGISTRY}-frontend:${TAG}
  ${REGISTRY}-api-gateway:${TAG}
  ... (all services)

Organization deploy (no build):
  git clone https://github.com/rahul1713/vulnshield-platform.git
  cd vulnshield-platform
  VULNSHIELD_TAG=${TAG} ./scripts/deploy-pull.sh

EOF
