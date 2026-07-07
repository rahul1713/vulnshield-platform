# VulnShield Deployment Guide

Deploy VulnShield with Docker Compose. For production-hardened sandbox deployments, prefer [SANDBOX_DEPLOYMENT.md](SANDBOX_DEPLOYMENT.md).

![Deployment flow](images/deployment-flow.png)

## Choose your deployment path

| Path | Command | Best for |
|------|---------|----------|
| **Sandbox (recommended)** | `make sandbox-env && make sandbox-up` | Staging, POC, security labs |
| **Development** | `cp .env.example .env && make up` | Local engineering |

---

## Sandbox deployment (recommended)

```bash
git clone https://github.com/rahul1713/vulnshield-platform.git
cd vulnshield-platform

make sandbox-env    # Generates .env.sandbox with random secrets
make sandbox-up     # Starts hardened stack
```

- Admin password printed once during `make sandbox-env`
- Only API (`127.0.0.1:8080`) and UI (`127.0.0.1:3000`) exposed
- Postgres, Redis, RabbitMQ, MinIO stay on internal Docker network
- Demo mode disabled at build time

Full checklist → [SANDBOX_DEPLOYMENT.md](SANDBOX_DEPLOYMENT.md)

---

## Development deployment

### Prerequisites

- Docker Engine 24+ and Docker Compose v2
- 16 GB RAM (32 GB with AI services)
- 50 GB disk

### Steps

```bash
git clone https://github.com/rahul1713/vulnshield-platform.git
cd vulnshield-platform

cp .env.example .env
# Edit .env — set JWT_SECRET, INIT_ADMIN_PASSWORD, database passwords
# Generate secrets: openssl rand -hex 32

make build
make up
docker compose ps
```

### Access URLs

| Service | URL |
|---------|-----|
| Dashboard | http://localhost:3000 |
| API Gateway | http://localhost:8080/api/v1 |
| Health | http://localhost:8080/health |

Log in with credentials from `INIT_ADMIN_PASSWORD` in your `.env` file.

---

## Environment configuration

Key variables (see `.env.example` for full list):

```bash
ENVIRONMENT=development
JWT_SECRET=<openssl rand -hex 32>
INIT_ADMIN_PASSWORD=<strong-password-min-12-chars>
POSTGRES_PASSWORD=<openssl rand -hex 24>
RABBITMQ_PASSWORD=<openssl rand -hex 24>
REDIS_PASSWORD=<openssl rand -hex 24>   # Required in sandbox/production
CORS_ORIGINS=http://localhost:3000

# Security AI — local Ollama + Qwen 3.6 only
OLLAMA_MODEL=qwen3.6
AI_SECURITY_LOCAL_ONLY=true
```

---

## AI services (optional)

Pull the local security AI model after the stack is running:

```bash
docker compose --profile ai up -d ollama
docker compose exec ollama ollama pull qwen3.6
docker compose up -d scanner-service ai-code-review ai-redteam
```

---

## Infrastructure services

| Service | Image | Purpose |
|---------|-------|---------|
| PostgreSQL 16 | `postgres:16-alpine` | Primary data store |
| Redis 7 | `redis:7-alpine` | Cache and job queues |
| RabbitMQ 3.13 | `rabbitmq:3.13-management-alpine` | Event messaging |
| MinIO | `minio/minio` | Evidence files and reports |
| Ollama | `ollama/ollama` | Local LLM for security AI |

Schema and seed data load automatically from `shared/database/init/` on first PostgreSQL start.

---

## Agent deployment

### Linux (Docker)

```bash
docker build -t vulnshield-linux-agent agents/linux/
docker run -d \
  -e VULNSHIELD_API_URL=https://your-gateway:8080/api/v1 \
  -e VULNSHIELD_API_TOKEN=your-agent-token \
  vulnshield-linux-agent
```

### Windows

```powershell
.\agents\windows\install.ps1 -ApiUrl "https://your-gateway:8080/api/v1" -ApiToken "your-token"
```

---

## Operations

```bash
make logs              # All service logs
make down              # Stop services
make clean             # Stop and remove volumes
docker compose logs -f auth-service   # Single service
```

### Database backup

```bash
docker compose exec postgres pg_dump -U vulnshield vulnshield > backup.sql
docker compose exec -T postgres psql -U vulnshield vulnshield < backup.sql
```

---

## Production considerations

1. Use [SANDBOX_DEPLOYMENT.md](SANDBOX_DEPLOYMENT.md) or Kubernetes (`k8s/`) for production
2. Terminate TLS at ingress (nginx, Traefik, cloud LB)
3. Store secrets in a vault — never commit `.env.sandbox` or `k8s/secrets.yaml`
4. Schedule PostgreSQL and MinIO backups
5. Enable LDAP/MFA per [ADMIN_MANUAL.md](ADMIN_MANUAL.md)
6. Restrict agent network access to API gateway only

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Services won't start | `docker compose logs` — check dependency health |
| Login fails | Verify `INIT_ADMIN_PASSWORD` was set before first auth-service start |
| Frontend API errors | Confirm `NEXT_PUBLIC_API_URL` matches gateway URL |
| AI features unavailable | `docker compose exec ollama ollama pull qwen3.6` |
| Sandbox secret validation fails | Regenerate with `make sandbox-env` — no weak defaults allowed |

---

## Related docs

- [INSTALLATION.md](INSTALLATION.md) — Full server install with agents and LDAP
- [CAPABILITIES.md](CAPABILITIES.md) — Platform operations reference
- [ARCHITECTURE.md](ARCHITECTURE.md) — System design
