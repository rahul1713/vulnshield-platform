# VulnShield — Organization Quick Start

## Option A: Pull from GitHub (recommended for your org)

No compiling on each laptop — images are on **GitHub Container Registry**.

```bash
git clone https://github.com/rahul1713/vulnshield-platform.git
cd vulnshield-platform
make deploy-pull
```

Wait for images to pull + Ollama model download (first run: 10–20 min). Then open:

**http://127.0.0.1:3002**

| Username | Password |
|----------|----------|
| `admin` | `Admin@123456` |

### Docker images (GHCR)

All services are published as:

```
ghcr.io/rahul1713/vulnshield-<service>:latest
```

Examples: `vulnshield-frontend`, `vulnshield-api-gateway`, `vulnshield-ai-code-review`, `vulnshield-scan-worker`, etc.

Pin a version:

```bash
VULNSHIELD_TAG=v1.0.0 make deploy-pull
```

### Private packages

If images are private, login first:

```bash
export GITHUB_TOKEN=$(gh auth token)
export GITHUB_USER=rahul1713
make deploy-pull
```

---

## Option B: Build locally (developers)

```bash
git clone https://github.com/rahul1713/vulnshield-platform.git
cd vulnshield-platform
make deploy
```

---

## Option C: Publish images (maintainers)

From a machine with Docker + `gh auth login`:

```bash
make publish-images TAG=latest
```

Or push to `main` on GitHub — the **Docker Publish** workflow builds and pushes all images automatically.

---

## URLs

| Service | URL |
|---------|-----|
| Dashboard | http://127.0.0.1:3002 |
| API | http://127.0.0.1:18080/api/v1 |
| Health | http://127.0.0.1:18080/health |

## Stop

```bash
make sandbox-down
```

## Requirements

- Docker Desktop 24+ / Compose v2
- 16 GB RAM, 50 GB disk (Ollama model ~23 GB)
- Ports **3002** and **18080** free

## Large code scan (100k+ LOC)

1. **AI Code Review** → **New Review**
2. Repo: `https://github.com/eslint/eslint.git` (pre-filled in sandbox)
3. Click **Run SAST** — completes in ~5–10 min
4. Click **PDF** to download report

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Image pull 404 | Run GitHub **Docker Publish** workflow or `make publish-images` |
| Failed to fetch | Use http://127.0.0.1:3002, hard refresh |
| PDF won't save | Hard refresh after update; check Downloads folder |
| Postgres unhealthy | Free Docker disk: `docker builder prune -f` |
