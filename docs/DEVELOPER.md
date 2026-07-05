# VulnShield Developer Guide

Guide for extending VulnShield microservices, adding collectors, and contributing to the platform.

## Repository Structure

```
vulnshield-platform/
├── agents/                  # Endpoint agents (Linux, Windows)
├── docs/                    # Documentation
├── frontend/                # Next.js dashboard
├── k8s/                     # Kubernetes manifests
├── services/                # Microservices
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
├── shared/
│   ├── database/init/       # SQL schema and seed data
│   └── python/              # Shared Python library
├── docker-compose.yml
├── Makefile
└── .env.example
```

## Development Setup

```bash
git clone https://github.com/your-org/vulnshield-platform.git
cd vulnshield-platform
cp .env.example .env
make build
make up
```

### Running a Single Service Locally

Services use the shared `vulnshield_common` library. Install it in editable mode:

```bash
cd shared/python
pip install -e ".[dev]"
```

Run a service with hot reload:

```bash
cd services/auth-service
uvicorn app.main:app --reload --port 8001
```

Infrastructure (PostgreSQL, Redis, RabbitMQ) must be running via Docker Compose.

## Creating a New Microservice

### 1. Scaffold the Service

```
services/my-service/
├── Dockerfile
├── requirements.txt
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── routes/
│   ├── models/
│   └── services/
└── tests/
    └── test_main.py
```

### 2. Use Shared Libraries

```python
from vulnshield_common.config import get_settings
from vulnshield_common.database import get_db
from vulnshield_common.auth import get_current_user
from vulnshield_common.messaging import publish_event

settings = get_settings()

@app.post("/my-endpoint")
async def my_endpoint(
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    await publish_event("vulnshield.events", "my.event", {"data": "value"})
    return {"status": "ok"}
```

### 3. Add to Docker Compose

```yaml
my-service:
  build:
    context: .
    dockerfile: services/my-service/Dockerfile
  container_name: vulnshield-my-service
  environment:
    <<: *common-env
  depends_on:
    postgres:
      condition: service_healthy
  networks:
    - vulnshield-net
```

### 4. Register Routes in API Gateway

Add proxy rules in `services/api-gateway/app/routes/` to forward `/api/v1/my-service/*` to the new service.

## Adding a Linux Agent Collector

Collectors live in `agents/linux/collectors/`. Each collector is a function returning a `dict`.

### Example: Collect Firewall Rules

```python
# agents/linux/collectors/firewall.py
import subprocess

def collect_firewall_rules() -> dict:
    result = subprocess.run(
        ["iptables", "-L", "-n", "--line-numbers"],
        capture_output=True, text=True, timeout=10, check=False,
    )
    return {
        "available": result.returncode == 0,
        "rules": result.stdout.splitlines() if result.returncode == 0 else [],
    }
```

Register in `agents/linux/collectors/__init__.py`:

```python
from collectors.firewall import collect_firewall_rules

COLLECTORS = {
    # ... existing collectors
    "firewall_rules": collect_firewall_rules,
}
```

Test locally:

```bash
cd agents/linux
python agent.py collect | jq '.firewall_rules'
```

## Adding Database Tables

1. Add migration SQL to `shared/database/init/001_schema.sql` (or a new numbered file)
2. Update `docs/ER_DIAGRAM.md` with the new entity
3. Add SQLAlchemy models in the relevant service's `app/models/`
4. Re-run migrations: `make migrate`

Follow existing conventions:
- UUID primary keys via `uuid_generate_v4()`
- `created_at` / `updated_at` timestamps with trigger
- JSONB for flexible metadata fields

## Event-Driven Integration

Services communicate asynchronously via RabbitMQ.

### Publishing Events

```python
from vulnshield_common.messaging import publish_event

await publish_event(
    exchange="vulnshield.events",
    routing_key="scan.completed",
    payload={"scan_id": str(scan.id), "findings_count": 42},
)
```

### Consuming Events

```python
from vulnshield_common.messaging import consume_events

async def handle_scan_completed(message: dict):
    scan_id = message["scan_id"]
    # Process the event

await consume_events(
    queue="risk-engine.scan-completed",
    routing_keys=["scan.completed"],
    handler=handle_scan_completed,
)
```

## API Conventions

- Base path: `/api/v1/`
- Authentication: `Authorization: Bearer <jwt>`
- Pagination: `?page=1&page_size=25`
- Filtering: `?severity=critical&status=open`
- Response envelope:

```json
{
  "data": [...],
  "total": 100,
  "page": 1,
  "page_size": 25
}
```

- Error format:

```json
{
  "detail": "Human-readable error message",
  "code": "RESOURCE_NOT_FOUND"
}
```

## Testing

```bash
# Run all tests
make test

# Run a specific service's tests
docker compose run --rm auth-service pytest /app/tests -v

# Run with coverage
docker compose run --rm auth-service pytest /app/tests --cov=app --cov-report=term-missing
```

Write tests using pytest with async support:

```python
import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app

@pytest.mark.asyncio
async def test_health():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")
        assert response.status_code == 200
```

## Linting

```bash
make lint

# Or directly with ruff
docker compose run --rm auth-service ruff check /app
docker compose run --rm auth-service ruff format /app --check
```

Configuration: services use `ruff` with line length 100, Python 3.12 target.

## Frontend Development

```bash
cd frontend
npm install
npm run dev
```

The dev server runs on http://localhost:3000 and proxies API calls to the gateway.

Key directories:
- `frontend/src/app/` — Next.js App Router pages
- `frontend/src/components/` — Reusable UI components
- `frontend/src/lib/api.ts` — API client with JWT handling

## LLM Integration

The shared LLM module supports multiple providers:

```python
from vulnshield_common.llm import get_llm_client

client = get_llm_client()
response = await client.complete(
    prompt="Analyze this code for SQL injection vulnerabilities",
    system="You are a security code reviewer.",
)
```

Configure via environment: `LLM_PROVIDER=ollama|openai|anthropic`

## Contributing Workflow

1. Create a feature branch from `main`
2. Make changes following existing conventions
3. Run `make lint && make test`
4. Update relevant documentation in `docs/`
5. Open a pull request with a clear description

CI runs lint, test, and Docker build on every PR (see `.github/workflows/ci.yml`).
