# VulnShield Platform Deployment Guide

This guide covers deploying VulnShield using Docker Compose for development and staging environments.

## Prerequisites

- Docker Engine 24+ and Docker Compose v2
- 16 GB RAM minimum (32 GB recommended with AI services)
- 50 GB disk space
- Ports available: 3000, 5432, 5672, 6379, 8080, 9000, 9001, 11434 (optional)

## Quick Start

```bash
# Clone the repository
git clone https://github.com/your-org/vulnshield-platform.git
cd vulnshield-platform

# Configure environment
cp .env.example .env
# Edit .env — change JWT_SECRET and database passwords for production

# Start all services
make up

# Verify services are running
docker compose ps
```

The platform will be available at:

| Service | URL |
|---------|-----|
| Frontend Dashboard | http://localhost:3000 |
| API Gateway | http://localhost:8080/api/v1 |
| RabbitMQ Management | http://localhost:15672 |
| MinIO Console | http://localhost:9001 |

Default credentials: `admin@vulnshield.local` / `Admin@123456`

## Service Profiles

### Core Platform (default)

Starts infrastructure and all application services:

```bash
docker compose up -d
```

### With AI Services

Includes Ollama for local LLM inference:

```bash
docker compose --profile ai up -d
```

Pull a model after Ollama starts:

```bash
docker compose exec ollama ollama pull llama3.2
```

## Environment Configuration

Key variables in `.env`:

```bash
# Security — change in production
JWT_SECRET=your-256-bit-secret-here
POSTGRES_PASSWORD=strong-random-password
RABBITMQ_PASSWORD=strong-random-password

# LLM provider
LLM_PROVIDER=ollama          # ollama | openai | anthropic
OLLAMA_MODEL=llama3.2

# Notifications (optional)
SMTP_HOST=smtp.company.com
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
```

See `.env.example` for the complete list.

## Infrastructure Services

### PostgreSQL

- Image: `postgres:16-alpine`
- Port: 5432
- Database auto-initialized from `shared/database/init/`
- Data persisted in `postgres_data` volume

### Redis

- Image: `redis:7-alpine`
- Port: 6379
- Used for session caching and scan job queues

### RabbitMQ

- Image: `rabbitmq:3.13-management-alpine`
- AMQP port: 5672, Management UI: 15672
- Default vhost: `vulnshield`

### MinIO

- Ports: 9000 (API), 9001 (Console)
- Bucket: `vulnshield-evidence` (created on first use)
- Stores vulnerability evidence files and generated reports

## Application Services

All application services are built from Dockerfiles in `services/` and share environment variables via the `x-common-env` anchor in `docker-compose.yml`.

Build all images:

```bash
make build
```

Build a single service:

```bash
docker compose build auth-service
```

## Database Management

Initial schema and seed data load automatically on first PostgreSQL startup. To re-run manually:

```bash
make migrate
make seed
```

## Agent Deployment

### Linux Agent (Docker)

```bash
docker build -t vulnshield-linux-agent agents/linux/

docker run -d \
  --name vulnshield-agent \
  -e VULNSHIELD_API_URL=https://your-gateway:8080/api/v1 \
  -e VULNSHIELD_API_TOKEN=your-agent-token \
  -v /etc/vulnshield/certs:/etc/vulnshield/certs:ro \
  vulnshield-linux-agent
```

### Linux Agent (systemd)

```bash
sudo mkdir -p /opt/vulnshield-agent /etc/vulnshield
sudo cp -r agents/linux/* /opt/vulnshield-agent/
sudo pip install -r /opt/vulnshield-agent/requirements.txt

cat << 'EOF' | sudo tee /etc/vulnshield/agent.env
VULNSHIELD_API_URL=https://your-gateway:8080/api/v1
VULNSHIELD_API_TOKEN=your-agent-token
VULNSHIELD_MTLS_ENABLED=true
EOF

sudo python /opt/vulnshield-agent/agent.py
```

### Windows Agent

Run as Administrator on the target host:

```powershell
.\agents\windows\install.ps1 `
  -ApiUrl "https://your-gateway:8080/api/v1" `
  -ApiToken "your-agent-token" `
  -EnableMtls
```

## Monitoring & Logs

View all service logs:

```bash
make logs
```

View a specific service:

```bash
docker compose logs -f auth-service
```

Health checks are configured on PostgreSQL, Redis, and RabbitMQ. The API Gateway waits for auth-service and database health before accepting traffic.

## Backup & Recovery

### Database Backup

```bash
docker compose exec postgres pg_dump -U vulnshield vulnshield > backup.sql
```

### Restore

```bash
docker compose exec -T postgres psql -U vulnshield vulnshield < backup.sql
```

### Volume Backup

```bash
docker run --rm \
  -v vulnshield-platform_postgres_data:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/postgres_backup.tar.gz /data
```

## Production Considerations

1. **Secrets**: Use Docker secrets or a vault (HashiCorp Vault, AWS Secrets Manager) instead of `.env` files
2. **TLS**: Terminate TLS at a reverse proxy (nginx, Traefik) in front of the API Gateway
3. **Scaling**: Use Kubernetes manifests in `k8s/` for horizontal scaling
4. **Monitoring**: Add Prometheus/Grafana for metrics; services expose `/metrics` endpoints
5. **Backups**: Schedule automated PostgreSQL and MinIO backups
6. **Network**: Place agents in a dedicated VLAN with firewall rules allowing only HTTPS to the gateway

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Services fail to start | Check `docker compose logs` for dependency errors |
| Database connection refused | Wait for PostgreSQL health check; verify credentials in `.env` |
| Frontend shows API errors | Confirm `NEXT_PUBLIC_API_URL` matches the gateway URL |
| RabbitMQ connection failed | Verify vhost `vulnshield` exists and credentials match |
| Ollama model not found | Run `docker compose exec ollama ollama pull llama3.2` |

## Cleanup

Remove all containers and volumes:

```bash
make clean
```
