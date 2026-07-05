# VulnShield Platform

A cloud-native vulnerability management platform with asset discovery, AI-powered code review, red team simulation, patch intelligence, risk scoring, and compliance mapping.

## Features

- **Asset Discovery** — Linux and Windows agents collect OS info, packages, services, ports, users, cron jobs, and patches
- **Vulnerability Scanning** — Agent-based, network, and web application scanning with CVE correlation
- **AI Code Review** — LLM-powered static analysis with OWASP/CWE mapping and fix recommendations
- **AI Red Team** — Automated attack simulation with MITRE ATT&CK technique mapping
- **Patch Intelligence** — CVE-to-patch mapping, vendor advisories, and EOL tracking
- **Risk Engine** — Composite scoring using CVSS, EPSS, CISA KEV, and business context
- **Compliance** — CIS Controls, NIST CSF, NIST 800-53, ISO 27001, PCI-DSS assessments
- **Reporting** — Executive, technical, compliance, and trending reports (PDF, Excel, CSV)
- **Notifications** — Email, Slack, Teams, and webhook alerting

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────────────────────┐
│   Frontend  │────▶│  API Gateway │────▶│  Microservices (12 services)    │
│  (Next.js)  │     │   (:8080)    │     │  auth, asset, scanner, AI, ...  │
└─────────────┘     └──────────────┘     └─────────────────────────────────┘
       ▲                                          │         │         │
       │                                          ▼         ▼         ▼
┌─────────────┐                            ┌──────────┐ ┌───────┐ ┌─────────┐
│ Linux/Win   │──── HTTPS/mTLS ──────────▶│PostgreSQL│ │ Redis │ │RabbitMQ │
│   Agents    │                            └──────────┘ └───────┘ └─────────┘
└─────────────┘
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed architecture diagrams.

## Quick Start

### Prerequisites

- Docker Engine 24+ and Docker Compose v2
- 16 GB RAM, 50 GB disk

### Start the Platform

```bash
git clone https://github.com/your-org/vulnshield-platform.git
cd vulnshield-platform
cp .env.example .env
make up
```

| Service | URL |
|---------|-----|
| Dashboard | http://localhost:3000 |
| API | http://localhost:8080/api/v1 |
| RabbitMQ UI | http://localhost:15672 |
| MinIO Console | http://localhost:9001 |

**Default login:** `admin@vulnshield.local` / `Admin@123456`

### Install a Linux Agent

```bash
# Docker
docker build -t vulnshield-linux-agent agents/linux/
docker run -d \
  -e VULNSHIELD_API_URL=http://host.docker.internal:8080/api/v1 \
  -e VULNSHIELD_API_TOKEN=your-token \
  vulnshield-linux-agent

# Or run directly
cd agents/linux
pip install -r requirements.txt
VULNSHIELD_API_URL=http://localhost:8080/api/v1 \
VULNSHIELD_API_TOKEN=your-token \
python agent.py
```

### Install a Windows Agent

```powershell
# Run as Administrator
.\agents\windows\install.ps1 `
  -ApiUrl "http://your-server:8080/api/v1" `
  -ApiToken "your-token"
```

## Project Structure

```
vulnshield-platform/
├── agents/              # Linux & Windows endpoint agents
├── docs/                # Architecture, deployment, user guides
├── frontend/            # Next.js dashboard
├── k8s/                 # Kubernetes manifests
├── services/            # 12 microservices
│   ├── api-gateway/
│   ├── auth-service/
│   ├── asset-service/
│   ├── scanner-service/
│   ├── web-scanner-service/
│   ├── ai-code-review/
│   ├── ai-redteam/
│   ├── patch-intelligence/
│   ├── risk-engine/
│   ├── reporting-service/
│   ├── compliance-service/
│   └── notification-service/
├── shared/              # Database schema & Python shared library
├── .github/workflows/   # CI/CD pipelines
├── docker-compose.yml
└── Makefile
```

## Microservices

| Service | Description |
|---------|-------------|
| **api-gateway** | Single entry point, JWT validation, routing |
| **auth-service** | Authentication, RBAC, LDAP/MFA |
| **asset-service** | Asset inventory, agent management |
| **scanner-service** | Vulnerability scan orchestration |
| **web-scanner-service** | OWASP web application scanning |
| **ai-code-review** | LLM-powered source code analysis |
| **ai-redteam** | AI attack simulation |
| **patch-intelligence** | CVE patch mapping |
| **risk-engine** | Composite risk scoring |
| **reporting-service** | Report generation (PDF/Excel/CSV) |
| **compliance-service** | Framework assessments |
| **notification-service** | Multi-channel alerting |

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/ARCHITECTURE.md) | System design with mermaid diagrams |
| [ER Diagram](docs/ER_DIAGRAM.md) | Database entity relationships |
| [Deployment](docs/DEPLOYMENT.md) | Docker Compose deployment guide |
| [Installation](docs/INSTALLATION.md) | Step-by-step installation |
| [Developer Guide](docs/DEVELOPER.md) | Extending services and agents |
| [User Manual](docs/USER_MANUAL.md) | End user dashboard guide |
| [Admin Manual](docs/ADMIN_MANUAL.md) | Platform administration |

## Development

```bash
make build          # Build all Docker images
make up             # Start services
make logs           # Tail logs
make test           # Run tests
make lint           # Run linters
make down           # Stop services
make clean          # Remove containers and volumes
```

## CI/CD

- **CI** (`.github/workflows/ci.yml`) — Lint, test, and build on push/PR
- **Docker Publish** (`.github/workflows/docker-publish.yml`) — Build and push images on version tags

## Kubernetes

Optional manifests in `k8s/` for production deployment:

```bash
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/postgres.yaml
kubectl apply -f k8s/redis.yaml
kubectl apply -f k8s/infrastructure.yaml
kubectl apply -f k8s/services.yaml
```

## Agent Collectors

### Linux Agent

Collects: OS info, installed packages (dpkg/rpm/apk), running processes, open ports, users, cron jobs, systemd services, kernel version/modules, security patches.

Supports HTTPS with mutual TLS. Configuration via `/etc/vulnshield/agent.env`.

### Windows Agent

Hybrid PowerShell/Python design. Collects: OS info, installed software (registry), security registry settings, services, scheduled tasks, open ports, hotfixes/pending updates, local users.

Install via `install.ps1` which registers a SYSTEM scheduled task.

## Technology Stack

| Component | Technology |
|-----------|-----------|
| Frontend | Next.js 14, React, TypeScript |
| Backend | Python 3.12, FastAPI, SQLAlchemy |
| Database | PostgreSQL 16 |
| Cache | Redis 7 |
| Messaging | RabbitMQ 3.13 |
| Storage | MinIO (S3-compatible) |
| LLM (Security AI) | Local Ollama + Qwen 3.6 only |
| Agents | Python, PowerShell |
| CI/CD | GitHub Actions |
| Orchestration | Docker Compose, Kubernetes |

## License

Proprietary. All rights reserved.
