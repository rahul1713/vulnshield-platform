#!/usr/bin/env bash
# VulnShield benchmark runner — reads credentials from .env.sandbox without printing them.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="${ROOT}/.env.sandbox"
API_BASE="${API_BASE:-http://127.0.0.1:18080/api/v1}"
REPO_URL="${REPO_URL:-https://github.com/eslint/eslint.git}"
WAPT_TARGET="${WAPT_TARGET:-http://testphp.vulnweb.com}"
WAPT_FALLBACK="${WAPT_FALLBACK:-http://zap:8080}"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: $ENV_FILE not found. Run: make sandbox-env" >&2
  exit 1
fi

# shellcheck disable=SC1090
set -a && source "$ENV_FILE" && set +a

if [[ -z "${INIT_ADMIN_PASSWORD:-}" ]]; then
  echo "ERROR: INIT_ADMIN_PASSWORD not set in .env.sandbox" >&2
  exit 1
fi

login_resp=$(curl -sS -X POST "${API_BASE}/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"${INIT_ADMIN_USERNAME:-admin}\",\"password\":\"${INIT_ADMIN_PASSWORD}\"}" \
  -w "\n__HTTP_CODE__%{http_code}")

login_http=$(echo "$login_resp" | sed -n 's/.*__HTTP_CODE__//p')
login_body=$(echo "$login_resp" | sed 's/__HTTP_CODE__.*//')

if [[ "$login_http" != "200" ]]; then
  echo "ERROR: login failed HTTP ${login_http}" >&2
  echo "$login_body" >&2
  exit 1
fi

TOKEN=$(echo "$login_body" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

auth_hdr=(-H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json')

echo "=== SAST: Code review on ${REPO_URL} ==="
sast_start=$(date +%s)
sast_resp=$(curl -sS -X POST "${API_BASE}/code-review" "${auth_hdr[@]}" \
  -d "{\"repository_url\":\"${REPO_URL}\",\"language\":\"javascript\",\"branch\":\"main\"}" \
  -w "\n__HTTP_CODE__%{http_code}")
sast_http=$(echo "$sast_resp" | sed -n 's/.*__HTTP_CODE__//p')
sast_body=$(echo "$sast_resp" | sed 's/__HTTP_CODE__.*//')
if [[ "$sast_http" != "201" && "$sast_http" != "200" ]]; then
  echo "ERROR: SAST create failed HTTP ${sast_http}" >&2
  echo "$sast_body" >&2
  exit 1
fi
review_id=$(echo "$sast_body" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
echo "Review ID: ${review_id}"

while true; do
  status_resp=$(curl -sf "${API_BASE}/code-review/${review_id}" "${auth_hdr[@]}")
  status=$(echo "$status_resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])")
  if [[ "$status" == "completed" || "$status" == "failed" ]]; then
    sast_end=$(date +%s)
    sast_duration=$((sast_end - sast_start))
    findings_count=$(echo "$status_resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('findings_count',0))")
    break
  fi
  sleep 5
done

findings_json=$(curl -sf "${API_BASE}/code-review/${review_id}/findings" "${auth_hdr[@]}")

echo "=== WAPT: Web scan ==="
wapt_target="$WAPT_TARGET"
wapt_code=$(curl -s -o /tmp/wapt-create.json -w "%{http_code}" -X POST "${API_BASE}/web-scans" "${auth_hdr[@]}" \
  -d "{\"name\":\"Benchmark WAPT\",\"target_url\":\"${wapt_target}\",\"crawl_depth\":2}")

if [[ "$wapt_code" == "403" || "$wapt_code" == "400" ]]; then
  echo "External target blocked (${wapt_code}); using sandbox fallback ${WAPT_FALLBACK}"
  wapt_target="$WAPT_FALLBACK"
  wapt_resp=$(curl -sf -X POST "${API_BASE}/web-scans" "${auth_hdr[@]}" \
    -d "{\"name\":\"Benchmark WAPT (sandbox)\",\"target_url\":\"${wapt_target}\",\"crawl_depth\":2}")
else
  [[ "$wapt_code" == "201" || "$wapt_code" == "200" ]] || { cat /tmp/wapt-create.json; exit 1; }
  wapt_resp=$(cat /tmp/wapt-create.json)
fi

scan_id=$(echo "$wapt_resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
echo "Scan ID: ${scan_id} target: ${wapt_target}"

wapt_start=$(date +%s)
while true; do
  scan_resp=$(curl -sf "${API_BASE}/web-scans/${scan_id}" "${auth_hdr[@]}")
  scan_status=$(echo "$scan_resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])")
  if [[ "$scan_status" == "completed" || "$scan_status" == "failed" ]]; then
    wapt_end=$(date +%s)
    wapt_duration=$((wapt_end - wapt_start))
    wapt_findings_count=$(echo "$scan_resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('findings_count',0))")
    break
  fi
  sleep 5
done

wapt_findings_json=$(curl -sf "${API_BASE}/web-scans/${scan_id}/findings" "${auth_hdr[@]}")

python3 - "$REPO_URL" "$sast_duration" "$status" "$findings_count" "$findings_json" \
  "$wapt_target" "$wapt_duration" "$scan_status" "$wapt_findings_count" "$wapt_findings_json" <<'PY'
import json, sys, subprocess

repo_url, sast_dur, sast_status, sast_fc, sast_findings = sys.argv[1:6]
wapt_target, wapt_dur, wapt_status, wapt_fc, wapt_findings = sys.argv[6:11]

repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")

# LOC from local clone if present
loc = "unknown"
try:
    r = subprocess.run(
        ["find", "/tmp/bench-repo", "-type", "f",
         "(", "-name", "*.js", "-o", "-name", "*.ts", "-o", "-name", "*.jsx", "-o", "-name", "*.tsx", "-o", "-name", "*.mjs", "-o", "-name", "*.cjs", ")"],
        capture_output=True, text=True, timeout=60,
    )
    if r.stdout.strip():
        wc = subprocess.run(["wc", "-l", *r.stdout.strip().split("\n")[:50000]], capture_output=True, text=True, timeout=120)
        for line in wc.stdout.strip().split("\n"):
            if "total" in line:
                loc = line.strip().split()[0]
except Exception:
    pass

sast_list = json.loads(sast_findings)
wapt_list = json.loads(wapt_findings)

print(json.dumps({
    "repo_name": repo_name,
    "repository_url": repo_url,
    "line_count_js_ts": loc,
    "sast": {
        "duration_seconds": int(sast_dur),
        "status": sast_status,
        "findings_count": int(sast_fc),
        "findings": [
            {k: f.get(k) for k in ("severity", "title", "file_path", "line_start", "category", "cwe_id")}
            for f in sast_list[:50]
        ],
    },
    "wapt": {
        "target": wapt_target,
        "duration_seconds": int(wapt_dur),
        "status": wapt_status,
        "findings_count": int(wapt_fc),
        "vulnerabilities": [
            {k: f.get(k) for k in ("severity", "title", "url", "vulnerability_type", "owasp_category", "cwe_id")}
            for f in wapt_list[:50]
        ],
    },
}, indent=2))
PY
