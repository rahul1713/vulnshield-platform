# VulnShield Installation Guide

Step-by-step installation for enterprise deployment including agents, LDAP, mTLS, and Kubernetes.

![Deployment flow](images/deployment-flow.png)

> **Quick start?** For most teams, [SANDBOX_DEPLOYMENT.md](SANDBOX_DEPLOYMENT.md) (`make sandbox-env && make sandbox-up`) is faster and already hardened.

---

## System requirements

### Platform server

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 4 cores | 8+ cores |
| RAM | 16 GB | 32 GB |
| Disk | 50 GB SSD | 200 GB SSD |
| OS | Ubuntu 22.04, RHEL 9, macOS 14+ | Ubuntu 22.04 LTS |

### Endpoint agents

| Platform | Requirements |
|----------|-------------|
| Linux | Python 3.12+, root or CAP_SYS_PTRACE |
| Windows | Server 2016+, Python 3.12+, PowerShell 5.1+, Administrator |

---

## Step 1: Install Docker

### Ubuntu/Debian

```bash
sudo apt-get update && sudo apt-get install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | sudo tee /etc/apt/sources.list.d/docker.list
sudo apt-get update && sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo usermod -aG docker $USER
```

### macOS

Install [Docker Desktop](https://www.docker.com/products/docker-desktop/).

---

## Step 2: Clone and configure secrets

```bash
git clone https://github.com/rahul1713/vulnshield-platform.git
cd vulnshield-platform
```

### Option A — Sandbox (recommended)

```bash
make sandbox-env    # Creates .env.sandbox with random secrets
make sandbox-up
```

Save the admin password printed by `make sandbox-env`.

### Option B — Custom development

```bash
cp .env.example .env
```

Generate and set secrets:

```bash
openssl rand -hex 32   # JWT_SECRET
openssl rand -hex 24   # POSTGRES_PASSWORD, RABBITMQ_PASSWORD, REDIS_PASSWORD
```

Edit `.env`:

```bash
JWT_SECRET=<generated>
INIT_ADMIN_PASSWORD=<strong-password-12+-chars>
POSTGRES_PASSWORD=<generated>
RABBITMQ_PASSWORD=<generated>
REDIS_PASSWORD=<generated>
CORS_ORIGINS=https://vulnshield.yourcompany.com
```

---

## Step 3: Build and start

```bash
make build
make up          # or: make sandbox-up
docker compose ps
```

All services should show `running` or `healthy`.

---

## Step 4: Verify installation

1. Open http://localhost:3000 (or your configured URL)
2. Log in with admin credentials from `INIT_ADMIN_PASSWORD`
3. Change password when prompted (`must_change_password` flag)
4. Verify dashboard loads with seed asset and CVE data

```bash
curl -s http://localhost:8080/health
curl -s http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"YOUR_PASSWORD"}'
```

---

## Step 5: AI model (optional)

Security AI uses **local Ollama + Qwen 3.6 only**:

```bash
docker compose --profile ai up -d ollama
docker compose exec ollama ollama pull qwen3.6
docker compose up -d scanner-service ai-code-review ai-redteam
curl -s http://localhost:11434/api/tags
```

---

## Step 6: Install endpoint agents

### Linux (systemd)

```bash
sudo mkdir -p /opt/vulnshield-agent /etc/vulnshield
# Copy agents/linux/* to /opt/vulnshield-agent/
sudo pip3 install -r /opt/vulnshield-agent/requirements.txt

sudo tee /etc/vulnshield/agent.env << 'EOF'
VULNSHIELD_API_URL=https://your-platform:8080/api/v1
VULNSHIELD_API_TOKEN=<token-from-admin-console>
VULNSHIELD_MTLS_ENABLED=false
VULNSHIELD_HEARTBEAT_INTERVAL=300
EOF

sudo systemctl enable --now vulnshield-agent
```

### Windows

```powershell
Set-ExecutionPolicy Bypass -Scope Process
.\install.ps1 -ApiUrl "https://your-platform:8080/api/v1" -ApiToken "<token>"
Get-ScheduledTask -TaskName VulnShieldAgent
```

---

## Step 7: Configure notifications (optional)

```bash
# In .env
SMTP_HOST=smtp.yourcompany.com
SMTP_PORT=587
SMTP_USER=alerts@yourcompany.com
SMTP_PASSWORD=<smtp-password>
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
```

```bash
docker compose up -d notification-service
```

---

## Step 8: LDAP SSO (optional)

```bash
LDAP_ENABLED=true
LDAP_SERVER=ldap://ldap.corp.local:389
LDAP_BASE_DN=dc=corp,dc=local
LDAP_BIND_DN=cn=vulnshield,ou=services,dc=corp,dc=local
LDAP_BIND_PASSWORD=<bind-password>
```

```bash
docker compose up -d auth-service
```

---

## Step 9: Kubernetes (production)

```bash
cp k8s/secrets.example.yaml k8s/secrets.yaml
# Edit secrets.yaml and configmap.yaml (CORS_ORIGINS, NEXT_PUBLIC_API_URL)

kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secrets.yaml
kubectl apply -f k8s/
kubectl apply -f k8s/network-policy.yaml
```

Set `NEXT_PUBLIC_API_URL` in ConfigMap to your **public ingress URL**, not cluster DNS.

---

## Post-installation checklist

- [ ] Admin password changed after first login
- [ ] All secrets rotated from example values
- [ ] `ENVIRONMENT=sandbox` or `production` set
- [ ] `NEXT_PUBLIC_ENABLE_DEMO_MODE=false`
- [ ] Agent registration tokens created
- [ ] At least one agent online in Assets
- [ ] Notifications tested
- [ ] Database backup scheduled
- [ ] Firewall: only 443/8080 exposed publicly
- [ ] TLS terminated at ingress
- [ ] LDAP/MFA enabled per policy

---

## Uninstall

```bash
make clean   # Docker

# Linux agent
sudo systemctl stop vulnshield-agent && sudo systemctl disable vulnshield-agent
sudo rm -rf /opt/vulnshield-agent /etc/vulnshield

# Windows agent
Unregister-ScheduledTask -TaskName VulnShieldAgent -Confirm:$false
```

---

## Related docs

- [DEPLOYMENT.md](DEPLOYMENT.md) — Docker Compose reference
- [ADMIN_MANUAL.md](ADMIN_MANUAL.md) — Ongoing administration
- [CAPABILITIES.md](CAPABILITIES.md) — Platform operations
