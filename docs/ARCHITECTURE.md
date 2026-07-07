# VulnShield Platform Architecture

VulnShield is a cloud-native vulnerability management platform built as microservices. It provides asset discovery, vulnerability scanning, AI-assisted code review, red team simulation, patch intelligence, risk scoring, compliance mapping, and reporting.

![Architecture overview](images/architecture-overview.png)

## High-Level Architecture

```mermaid
flowchart TB
    subgraph Clients["Clients"]
        Browser["Web Browser"]
        LinuxAgent["Linux Agent"]
        WinAgent["Windows Agent"]
        CI["CI/CD Pipelines"]
    end

    subgraph Edge["Edge Layer"]
        FE["Frontend<br/>(Next.js :3000)"]
        GW["API Gateway<br/>(:8080)"]
    end

    subgraph Core["Core Services"]
        AUTH["Auth Service"]
        ASSET["Asset Service"]
        SCAN["Scanner Service"]
        WEBSCAN["Web Scanner Service"]
    end

    subgraph Intelligence["Intelligence Services"]
        PATCH["Patch Intelligence"]
        RISK["Risk Engine"]
        COMPLY["Compliance Service"]
    end

    subgraph AI["AI Services"]
        CODEREview["AI Code Review"]
        REDTEAM["AI Red Team"]
        OLLAMA["Ollama LLM"]
    end

    subgraph Support["Support Services"]
        REPORT["Reporting Service"]
        NOTIFY["Notification Service"]
    end

    subgraph Data["Data Layer"]
        PG[("PostgreSQL")]
        REDIS[("Redis")]
        RMQ[("RabbitMQ")]
        MINIO[("MinIO")]
    end

    Browser --> FE
    FE --> GW
    LinuxAgent -->|HTTPS/mTLS| GW
    WinAgent -->|HTTPS/mTLS| GW
    CI --> GW

    GW --> AUTH
    GW --> ASSET
    GW --> SCAN
    GW --> WEBSCAN
    GW --> PATCH
    GW --> RISK
    GW --> COMPLY
    GW --> CODEREview
    GW --> REDTEAM
    GW --> REPORT
    GW --> NOTIFY

    AUTH --> PG
    AUTH --> REDIS
    ASSET --> PG
    ASSET --> RMQ
    SCAN --> PG
    SCAN --> RMQ
    SCAN --> REDIS
    WEBSCAN --> PG
    WEBSCAN --> RMQ
    PATCH --> PG
    RISK --> PG
    RISK --> RMQ
    COMPLY --> PG
    CODEREview --> PG
    CODEREview --> RMQ
    REDTEAM --> PG
    REDTEAM --> RMQ
    REPORT --> PG
    REPORT --> MINIO
    NOTIFY --> PG
    NOTIFY --> RMQ

    CODEREview -.-> OLLAMA
    REDTEAM -.-> OLLAMA
```

## Service Responsibilities

| Service | Port (internal) | Purpose |
|---------|-----------------|---------|
| **API Gateway** | 8080 | Single entry point, JWT validation, request routing, rate limiting |
| **Auth Service** | 8001 | User authentication, RBAC, JWT issuance, LDAP/MFA support |
| **Asset Service** | 8002 | Asset inventory, agent registration, software/port tracking |
| **Scanner Service** | 8003 | Network and agent-based vulnerability scanning orchestration |
| **Web Scanner Service** | 8004 | OWASP web application scanning (SQLi, XSS, CSRF, etc.) |
| **AI Code Review** | 8005 | LLM-powered static analysis of source code repositories |
| **AI Red Team** | 8006 | AI-driven attack simulation with MITRE ATT&CK mapping |
| **Patch Intelligence** | 8007 | CVE-to-patch mapping, vendor advisories, EOL tracking |
| **Risk Engine** | 8008 | Composite risk scoring (CVSS, EPSS, KEV, business context) |
| **Reporting Service** | 8009 | PDF/Excel/CSV report generation, stored in MinIO |
| **Compliance Service** | 8010 | CIS, NIST, ISO 27001, PCI-DSS framework assessments |
| **Notification Service** | 8011 | Email, Slack, Teams, webhook alerting |
| **Frontend** | 3000 | Next.js dashboard for SOC analysts and administrators |

## Data Flow: Agent Inventory

```mermaid
sequenceDiagram
    participant Agent as Linux/Windows Agent
    participant GW as API Gateway
    participant Asset as Asset Service
    participant Scan as Scanner Service
    participant Risk as Risk Engine
    participant PG as PostgreSQL
    participant RMQ as RabbitMQ

    Agent->>GW: POST /agents/register (mTLS)
    GW->>Asset: Forward registration
    Asset->>PG: Upsert agent + asset record
    Asset-->>Agent: agent_id, config

    loop Every 5 minutes
        Agent->>GW: POST /agents/{id}/heartbeat
        GW->>Asset: Update last_heartbeat
    end

    loop Every hour
        Agent->>GW: POST /agents/{id}/inventory
        GW->>Asset: Store software, ports, users
        Asset->>PG: Update asset_software, asset_ports
        Asset->>RMQ: Publish inventory.received
        RMQ->>Scan: Trigger vulnerability correlation
        Scan->>PG: Match CVEs to installed software
        Scan->>RMQ: Publish scan.completed
        RMQ->>Risk: Recalculate asset risk scores
    end
```

## Messaging Architecture

RabbitMQ handles asynchronous event processing between services:

| Exchange | Routing Key | Consumer |
|----------|-------------|----------|
| `vulnshield.events` | `inventory.received` | Scanner Service |
| `vulnshield.events` | `scan.completed` | Risk Engine, Notification Service |
| `vulnshield.events` | `vulnerability.critical` | Notification Service |
| `vulnshield.events` | `report.generated` | Notification Service |

## Authentication & Authorization

```mermaid
flowchart LR
    User["User"] -->|Login| AUTH["Auth Service"]
    AUTH -->|JWT Access Token| User
    User -->|Bearer Token| GW["API Gateway"]
    GW -->|Validate JWT| AUTH
    GW -->|Check RBAC permissions| Service["Microservice"]
```

Roles defined in the database: `administrator`, `security_manager`, `soc_analyst`, `developer`, `auditor`, `read_only`. Permissions are stored as JSON arrays on the `roles` table and enforced at the API Gateway layer.

## Agent Communication

Agents communicate over HTTPS with optional mutual TLS:

- **Registration**: `POST /api/v1/agents/register`
- **Heartbeat**: `POST /api/v1/agents/{agent_id}/heartbeat`
- **Inventory**: `POST /api/v1/agents/{agent_id}/inventory`

Certificate paths (Linux): `/etc/vulnshield/certs/{client.crt, client.key, ca.crt}`

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Next.js 14, React, TypeScript, Tailwind CSS |
| API Gateway | Python, FastAPI |
| Microservices | Python 3.12, FastAPI, SQLAlchemy (async) |
| Database | PostgreSQL 16 |
| Cache | Redis 7 |
| Message Queue | RabbitMQ 3.13 |
| Object Storage | MinIO (S3-compatible) |
| LLM | Ollama (local) or OpenAI/Anthropic (cloud) |
| Agents | Python 3.12, PowerShell 5.1+ |
| Container Runtime | Docker, Docker Compose |
| Orchestration | Kubernetes (optional) |

## Shared Libraries

The `shared/python/vulnshield_common` package provides cross-service utilities:

- `config.py` — Pydantic settings with environment variable binding
- `auth.py` — JWT creation/validation, password hashing, RBAC
- `database.py` — Async SQLAlchemy session management
- `messaging.py` — RabbitMQ publisher/consumer helpers
- `storage.py` — MinIO/S3 file operations
- `llm.py` — Multi-provider LLM client (Ollama, OpenAI, Anthropic)

## Deployment Topologies

### Development (Docker Compose)

All services run on a single host via `docker compose up`. Infrastructure (PostgreSQL, Redis, RabbitMQ, MinIO) and application services share a bridge network.

### Production (Kubernetes)

Services are deployed as Deployments with HorizontalPodAutoscalers. PostgreSQL and Redis use StatefulSets with persistent volumes. Ingress routes external traffic to the API Gateway and Frontend.

See [DEPLOYMENT.md](DEPLOYMENT.md) for Docker Compose instructions and `k8s/` for Kubernetes manifests.
