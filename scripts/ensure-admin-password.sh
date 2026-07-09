#!/usr/bin/env bash
# Sync admin password in Postgres to INIT_ADMIN_PASSWORD from .env.sandbox.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="${1:-${ROOT}/.env.sandbox}"

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "Missing ${ENV_FILE}" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "${ENV_FILE}"

if [[ -z "${INIT_ADMIN_PASSWORD:-}" ]]; then
  echo "INIT_ADMIN_PASSWORD is not set in ${ENV_FILE}" >&2
  exit 1
fi

USERNAME="${INIT_ADMIN_USERNAME:-admin}"
EMAIL="${INIT_ADMIN_EMAIL:-admin@vulnshield.local}"

echo "Ensuring admin user '${USERNAME}' password matches .env.sandbox ..."

docker compose --env-file "${ENV_FILE}" -f "${ROOT}/docker-compose.yml" -f "${ROOT}/docker-compose.sandbox.yml" \
  exec -T \
  -e INIT_ADMIN_PASSWORD="${INIT_ADMIN_PASSWORD}" \
  -e INIT_ADMIN_USERNAME="${USERNAME}" \
  -e INIT_ADMIN_EMAIL="${EMAIL}" \
  auth-service python - <<'PY'
import asyncio
import os
from sqlalchemy import text
from vulnshield_common.auth import hash_password
from vulnshield_common.database import AsyncSessionLocal

password = os.environ["INIT_ADMIN_PASSWORD"]
username = os.environ.get("INIT_ADMIN_USERNAME", "admin")
email = os.environ.get("INIT_ADMIN_EMAIL", "admin@vulnshield.local")
role_id = "a0000000-0000-0000-0000-000000000001"
pwd_hash = hash_password(password)

async def main():
    async with AsyncSessionLocal() as db:
        r = await db.execute(text("SELECT COUNT(*) FROM users"))
        count = r.scalar_one()
        if count == 0:
            await db.execute(
                text("""
                    INSERT INTO users (id, email, username, password_hash, first_name, last_name, role_id, must_change_password)
                    VALUES (
                        'b0000000-0000-0000-0000-000000000001',
                        :email, :username, :pwd_hash, 'System', 'Administrator', :role_id, FALSE
                    )
                """),
                {"email": email, "username": username, "pwd_hash": pwd_hash, "role_id": role_id},
            )
        else:
            await db.execute(
                text("""
                    UPDATE users SET password_hash = :pwd_hash, must_change_password = FALSE,
                        failed_login_attempts = 0, locked_until = NULL
                    WHERE username = :username
                """),
                {"pwd_hash": pwd_hash, "username": username},
            )
        await db.commit()

asyncio.run(main())
print("Admin password synchronized.")
PY
