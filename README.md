# VulnShield Platform

**Enterprise vulnerability management** — asset discovery, scanning, AI-assisted analysis, risk prioritization, compliance, and reporting. Built as cloud-native microservices with Docker Compose and Kubernetes support.

[![CI](https://github.com/rahul1713/vulnshield-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/rahul1713/vulnshield-platform/actions/workflows/ci.yml)

---

## Deploy in one command (organization sandbox)

### For your organization (pull pre-built images — fastest)

```bash
git clone https://github.com/rahul1713/vulnshield-platform.git
cd vulnshield-platform
make deploy-pull
```

Images: `ghcr.io/rahul1713/vulnshield-*:latest` on GitHub Container Registry.

### Build from source (developers)

```bash
git clone https://github.com/rahul1713/vulnshield-platform.git
cd vulnshield-platform
make deploy
```

Then open **http://127.0.0.1:3002** and sign in:

| Field | Value |
|-------|--------|
| Username | `admin` |
| Password | `Admin@123456` |

Full quick-start → [GETTING_STARTED.md](GETTING_STARTED.md). Security checklist → [docs/SANDBOX_DEPLOYMENT.md](docs/SANDBOX_DEPLOYMENT.md)

| After deploy | URL |
|--------------|-----|
| **Dashboard** | http://127.0.0.1:3002 |
| **API** | http://127.0.0.1:18080/api/v1 |
| **Health check** | http://127.0.0.1:18080/health |

### Legacy two-step deploy

```bash
make sandbox-env   # optional if .env.sandbox already exists
make sandbox-up
```


### Other deployment options

| Method | When to use | Guide |
|--------|-------------|-------|
| **Sandbox (Docker)** | Staging, POC, isolated lab | [SANDBOX_DEPLOYMENT.md](docs/SANDBOX_DEPLOYMENT.md) |
| **Development (Docker)** | Local engineering | [DEPLOYMENT.md](docs/DEPLOYMENT.md) |
| **Kubernetes** | Production / enterprise scale | [INSTALLATION.md](docs/INSTALLATION.md) + `k8s/` |

**Requirements:** Docker 24+, Compose v2, 16 GB RAM, 50 GB disk.

---

## What VulnShield does

![Operations workflow](docs/images/operations-workflow.png)

VulnShield runs a continuous **Discover → Scan → Correlate → Prioritize → Remediate** loop across your infrastructure.

![Dashboard overview](docs/images/dashboard-overview.png)

---

## Platform capabilities & operations

Each module below maps to a **sidebar section** in the dashboard and a **microservice** in the backend.

### Asset management
| Operation | What it does |
|-----------|--------------|
| **Discover assets** | Linux/Windows agents collect OS, packages, ports, users, services, and patches |
| **View inventory** | Search and filter servers, workstations, and cloud assets by criticality, OS, tags |
| **Track changes** | History of asset metadata, software inventory, and open ports over time |

### Vulnerability scanning
| Operation | What it does |
|-----------|--------------|
| **New scan** | Launch agent-based, SSH/WinRM, network, CIS, or web-app scans from the Scans page |
| **Start / cancel scan** | Control running jobs; status updates in real time (queued → running → completed) |
| **View findings** | CVE correlation with CVSS, EPSS, and CISA KEV data |
| **Update status** | Triage vulnerabilities: open → in progress → mitigated → resolved / false positive |

### Web application security (DAST)
| Operation | What it does |
|-----------|--------------|
| **Start web scan** | Crawl and test a target URL for OWASP Top 10 issues |
| **Review findings** | SQLi, XSS, missing headers, and other DAST results with severity |

### AI code review
| Operation | What it does |
|-----------|--------------|
| **New review** | Submit a repository URL for LLM-powered static security analysis |
| **View findings** | OWASP/CWE-mapped issues with remediation guidance |
| **Model** | Local **Ollama + Qwen 3.6 only** — source code never sent to cloud LLMs |

### AI red team
| Operation | What it does |
|-----------|--------------|
| **New campaign** | Launch automated adversary simulation against defined scope |
| **Attack paths** | MITRE ATT&CK-mapped findings and executive summary |
| **Model** | Local **Ollama + Qwen 3.6 only** |

### Patch intelligence
| Operation | What it does |
|-----------|--------------|
| **CVE lookup** | Map vulnerabilities to available vendor patches |
| **EOL tracking** | End-of-life status for affected software |
| **Advisory feed** | Vendor security bulletin references |

### Risk engine
| Operation | What it does |
|-----------|--------------|
| **Risk scoring** | Composite score: CVSS + EPSS + KEV + asset criticality + exposure |
| **Heatmap** | Visual risk distribution across assets and categories |
| **Prioritization** | Rank what to fix first based on business context |

### Compliance
| Operation | What it does |
|-----------|--------------|
| **Run assessment** | Score against CIS Controls, NIST CSF, NIST 800-53, ISO 27001, PCI-DSS |
| **Gap analysis** | Passed vs. failed controls with remediation mapping |
| **Trend tracking** | Compliance score over time |

### Reporting
| Operation | What it does |
|-----------|--------------|
| **Executive report** | High-level risk posture for leadership (PDF) |
| **Technical report** | Detailed findings for engineering teams |
| **Compliance report** | Framework-specific evidence (PDF, Excel, CSV) |
| **Export** | Scheduled or on-demand report generation |

### Notifications
| Operation | What it does |
|-----------|--------------|
| **Email alerts** | SMTP notifications for critical findings and scan completion |
| **Slack / Teams** | Webhook integration for SOC channels |
| **Custom webhooks** | Push events to SIEM or ticketing systems |

### Administration
| Operation | What it does |
|-----------|--------------|
| **User & RBAC** | Roles: administrator, security manager, SOC analyst, developer, auditor |
| **Audit logs** | Immutable record of logins, scan actions, and config changes |
| **Agent tokens** | Register Linux/Windows agents with scoped API tokens |
| **LDAP / MFA** | Enterprise SSO and TOTP multi-factor authentication |

---

## Architecture

![Architecture overview](docs/images/architecture-overview.png)

```
Browser / Agents  →  API Gateway (:8080)  →  12 Microservices  →  PostgreSQL / Redis / RabbitMQ / MinIO
```

| Service | Port (internal) | Purpose |
|---------|-----------------|---------|
| api-gateway | 8080 | JWT validation, routing, TLS termination point |
| auth-service | 8001 | Login, RBAC, audit, LDAP, MFA |
| asset-service | 8002 | Asset inventory and discovery |
| scanner-service | 8003 | Vulnerability scans, agents, CVE correlation |
| web-scanner-service | 8004 | DAST web application scanning |
| ai-code-review | 8005 | LLM code security analysis |
| ai-redteam | 8006 | Adversary simulation |
| patch-intelligence | 8007 | Patch and EOL mapping |
| risk-engine | 8008 | Composite risk scoring |
| reporting-service | 8009 | PDF / Excel / CSV reports |
| compliance-service | 8010 | Framework assessments |
| notification-service | 8011 | Email, Slack, Teams alerts |

Detailed diagrams → [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

---

## Endpoint agents

### Linux agent
Collects OS info, packages (dpkg/rpm/apk), processes, ports, users, cron, systemd services, kernel modules, and security patches. Supports HTTPS and mTLS.

```bash
docker build -t vulnshield-linux-agent agents/linux/
docker run -d \
  -e VULNSHIELD_API_URL=http://host.docker.internal:8080/api/v1 \
  -e VULNSHIELD_API_TOKEN=your-agent-token \
  vulnshield-linux-agent
```

### Windows agent
PowerShell/Python hybrid. Collects OS, registry software, services, scheduled tasks, ports, hotfixes, and local users.

```powershell
.\agents\windows\install.ps1 -ApiUrl "https://your-server:8080/api/v1" -ApiToken "your-token"
```

---

## Documentation

| Document | Audience | Contents |
|----------|----------|----------|
| [CAPABILITIES.md](docs/CAPABILITIES.md) | Everyone | Full feature reference with operations |
| [SANDBOX_DEPLOYMENT.md](docs/SANDBOX_DEPLOYMENT.md) | DevOps / Security | Hardened sandbox deploy + checklist |
| [DEPLOYMENT.md](docs/DEPLOYMENT.md) | DevOps | Docker Compose deployment |
| [INSTALLATION.md](docs/INSTALLATION.md) | DevOps | Step-by-step install + agents + LDAP |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Architects | System design, data flow, mermaid diagrams |
| [USER_MANUAL.md](docs/USER_MANUAL.md) | SOC / Analysts | Dashboard walkthrough |
| [ADMIN_MANUAL.md](docs/ADMIN_MANUAL.md) | Admins | Users, agents, backups, hardening |
| [DEVELOPER.md](docs/DEVELOPER.md) | Engineers | Extending services and agents |
| [ER_DIAGRAM.md](docs/ER_DIAGRAM.md) | DBAs | Database entity relationships |

---

## Development

```bash
make build          # Build Docker images
make up             # Start development stack
make logs           # Tail service logs
make test           # Run tests
make lint           # Run linters
make sandbox-up     # Start hardened sandbox
make clean          # Remove containers and volumes
```

### Local UI-only mode (no backend)

```bash
# frontend/.env.local
NEXT_PUBLIC_ENABLE_DEMO_MODE=true
NEXT_PUBLIC_DEMO_USERNAME=admin
NEXT_PUBLIC_DEMO_PASSWORD=your-local-password
```

Never enable demo mode in sandbox or production builds.

---

## Technology stack

| Layer | Technology |
|-------|------------|
| Frontend | Next.js 14, React, TypeScript, MUI |
| Backend | Python 3.12, FastAPI, SQLAlchemy |
| Database | PostgreSQL 16 |
| Cache / Queue | Redis 7, RabbitMQ 3.13 |
| Object storage | MinIO (S3-compatible) |
| Security AI | Ollama + Qwen 3.6 (local only) |
| Agents | Python, PowerShell |
| CI/CD | GitHub Actions |
| Orchestration | Docker Compose, Kubernetes |

---

## Security highlights

- No hardcoded credentials — admin bootstrapped via `INIT_ADMIN_PASSWORD`
- Startup secret validation in sandbox/production
- CORS locked to explicit origins
- Redis authentication required in sandbox
- OpenAPI docs disabled in production
- JWT on all API routes including ingestion
- mTLS fail-closed for agents in protected environments

---

## License

Proprietary. All rights reserved.
