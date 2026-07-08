# VulnShield Sandbox Deployment

Hardened deployment for **staging, POC, and isolated security labs**. No hardcoded credentials, no demo data leakage, infrastructure ports kept internal.

![Deployment flow](images/deployment-flow.png)

## Security guarantees (sandbox)

| Control | Implementation |
|---------|----------------|
| No default admin password | Admin created from `INIT_ADMIN_PASSWORD` env var at first boot |
| Demo/mock mode disabled | `NEXT_PUBLIC_ENABLE_DEMO_MODE=false` (build-time) |
| No demo corp.local seed data | Only RBAC roles + compliance frameworks load at init; run `make seed` for dev sample data only |
| No silent mock chart fallbacks | Dashboard charts stay empty when API returns no data (unless demo mode is on) |
| Secret validation | Services exit on startup if weak/default secrets detected |
| CORS locked down | Explicit `CORS_ORIGINS` required in sandbox |
| Redis auth | `--requirepass` enforced in sandbox |
| No OpenAPI docs | `/docs` disabled in sandbox/production |
| No Prometheus on public net | `/metrics` not mounted in protected environments |
| Ingestion auth | API gateway requires JWT for `/api/v1/ingestion` |
| mTLS fail-closed | Agent mTLS bypass disabled in sandbox/production |

## Quick start (Docker Compose)

```bash
# 1. Generate secrets (prints admin password once — save it securely)
./scripts/generate-sandbox-env.sh .env.sandbox

# 2. Start sandbox stack (only API + UI exposed on localhost)
docker compose --env-file .env.sandbox \
  -f docker-compose.yml \
  -f docker-compose.sandbox.yml \
  up -d --build

# 3. Open UI
open http://localhost:3000
```

Log in with the admin credentials printed by step 1. You will be prompted to change the password (`must_change_password=true`).

## Kubernetes

```bash
# Never commit real secrets
cp k8s/secrets.example.yaml k8s/secrets.yaml
# Edit k8s/secrets.yaml with openssl-generated values
# Edit k8s/configmap.yaml — set CORS_ORIGINS and NEXT_PUBLIC_API_URL to your ingress URL

kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secrets.yaml
kubectl apply -f k8s/
```

Apply `k8s/network-policy.yaml` when your cluster supports NetworkPolicy.

## Local development (optional demo mode)

For UI-only development without a backend:

```bash
cp frontend/.env.local.example frontend/.env.local
# Set NEXT_PUBLIC_ENABLE_DEMO_MODE=true
# Set NEXT_PUBLIC_DEMO_USERNAME and NEXT_PUBLIC_DEMO_PASSWORD
npm run dev
```

**Never** set `NEXT_PUBLIC_ENABLE_DEMO_MODE=true` in sandbox or production builds.

## Pre-deploy checklist

- [ ] All secrets generated with `openssl rand` (not example values)
- [ ] `.env.sandbox` / `k8s/secrets.yaml` not committed to git
- [ ] `ENVIRONMENT=sandbox` set for all services
- [ ] `CORS_ORIGINS` matches your frontend URL exactly
- [ ] `NEXT_PUBLIC_API_URL` points to public API ingress (not cluster DNS)
- [ ] `NEXT_PUBLIC_ENABLE_DEMO_MODE=false`
- [ ] TLS terminated at ingress / load balancer
- [ ] Postgres/Redis/RabbitMQ/MinIO not exposed to public internet
- [ ] Rotate `INIT_ADMIN_PASSWORD` after first login

## Data isolation

- Sandbox uses dedicated Docker volumes / K8s PVCs
- No production data should be mounted into sandbox
- Fresh Postgres init loads schema + RBAC roles only — **not** fake corp.local assets or vulnerabilities (`make seed` is development-only)
- Web scanner and red team stub engines mark findings as **simulated** when real scanning/LLM is unavailable
- AI features use local Ollama (`make sandbox-up` includes the `ai` profile) — source code sent to LLM stays in your network
- Audit logs record actions but never passwords or tokens
