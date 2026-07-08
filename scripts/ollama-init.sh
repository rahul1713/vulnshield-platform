#!/usr/bin/env bash
# Wait for Ollama and pull the configured security model (default: qwen3.6).
set -euo pipefail

OLLAMA_HOST="${OLLAMA_HOST:-http://ollama:11434}"
MODEL="${OLLAMA_MODEL:-qwen3.6}"
MAX_WAIT="${OLLAMA_INIT_MAX_WAIT:-300}"

echo "Waiting for Ollama at ${OLLAMA_HOST} (max ${MAX_WAIT}s)..."
elapsed=0
until curl -sf "${OLLAMA_HOST}/api/tags" >/dev/null 2>&1; do
  sleep 2
  elapsed=$((elapsed + 2))
  if [ "${elapsed}" -ge "${MAX_WAIT}" ]; then
    echo "ERROR: Ollama did not become healthy within ${MAX_WAIT}s" >&2
    exit 1
  fi
done

echo "Ollama is healthy."

if curl -sf "${OLLAMA_HOST}/api/tags" | grep -q "\"name\":\"${MODEL}\""; then
  echo "Model ${MODEL} already present — skipping pull."
  exit 0
fi

echo "Pulling model ${MODEL}..."
curl -sf -X POST "${OLLAMA_HOST}/api/pull" \
  -H 'Content-Type: application/json' \
  -d "{\"name\":\"${MODEL}\"}"

echo "Model ${MODEL} ready."
