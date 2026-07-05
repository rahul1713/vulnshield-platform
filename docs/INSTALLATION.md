# VulnShield Platform Installation Guide

Step-by-step instructions for installing VulnShield on a fresh server.

## System Requirements

### Server (Platform)

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 4 cores | 8+ cores |
| RAM | 16 GB | 32 GB |
| Disk | 50 GB SSD | 200 GB SSD |
| OS | Ubuntu 22.04 LTS, RHEL 9, macOS 14+ | Ubuntu 22.04 LTS |

### Endpoint Agents

| Platform | Requirements |
|----------|-------------|
| Linux | Python 3.12+, root or CAP_SYS_PTRACE for full collection |
| Windows | Windows Server 2016+, Python 3.12+, PowerShell 5.1+, Administrator |

## Step 1: Install Docker

### Ubuntu/Debian

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | sudo tee /etc/apt/sources.list.d/docker.list
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo usermod -aG docker $USER
```

### macOS

Install [Docker Desktop](https://www.docker.com/products/docker-desktop/) and ensure it is running.

## Step 2: Clone and Configure

```bash
git clone https://github.com/your-org/vulnshield-platform.git
cd vulnshield-platform
cp .env.example .env
```

Edit `.env` and set production values:

```bash
# Generate a secure JWT secret
openssl rand -hex 32

# Set in .env
JWT_SECRET=<generated-value>
POSTGRES_PASSWORD=<strong-password>
RABBITMQ_PASSWORD=<strong-password>
MINIO_SECRET_KEY=<strong-password>
```

## Step 3: Build and Start

```bash
# Build all Docker images
make build

# Start the platform
make up

# Verify all services are healthy
docker compose ps
```

Expected output: all services showing `running` or `healthy` status.

## Step 4: Verify Installation

1. Open http://localhost:3000 in your browser
2. Log in with `admin@vulnshield.local` / `Admin@123456`
3. Change the default password immediately (Settings → Profile)
4. Verify the dashboard loads asset and vulnerability data from seed records

Test the API:

```bash
curl -s http://localhost:8080/api/v1/health | jq .
```

## Step 5: Enable AI Services (Optional)

```bash
docker compose --profile ai up -d ollama
docker compose exec ollama ollama pull llama3.2
docker compose up -d ai-code-review ai-redteam
```

Verify LLM connectivity:

```bash
curl -s http://localhost:11434/api/tags | jq .
```

## Step 6: Configure Notifications (Optional)

Edit `.env`:

```bash
SMTP_HOST=smtp.yourcompany.com
SMTP_PORT=587
SMTP_USER=alerts@yourcompany.com
SMTP_PASSWORD=your-smtp-password
SMTP_FROM=noreply@vulnshield.local

SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T000/B000/XXXX
```

Restart the notification service:

```bash
docker compose up -d notification-service
```

## Step 7: Install Endpoint Agents

### Linux Server

```bash
# On the target Linux server
sudo mkdir -p /opt/vulnshield-agent /etc/vulnshield/certs

# Copy agent files from the platform server
scp -r user@platform-server:/path/to/vulnshield-platform/agents/linux/* /opt/vulnshield-agent/

# Install dependencies
sudo pip3 install -r /opt/vulnshield-agent/requirements.txt

# Configure
sudo tee /etc/vulnshield/agent.env << 'EOF'
VULNSHIELD_API_URL=https://your-platform:8080/api/v1
VULNSHIELD_API_TOKEN=<token-from-admin-console>
VULNSHIELD_MTLS_ENABLED=false
VULNSHIELD_HEARTBEAT_INTERVAL=300
VULNSHIELD_INVENTORY_INTERVAL=3600
EOF

# Test collection locally
sudo python3 /opt/vulnshield-agent/agent.py collect | head -20

# Run as systemd service
sudo tee /etc/systemd/system/vulnshield-agent.service << 'EOF'
[Unit]
Description=VulnShield Linux Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/vulnshield-agent/agent.py
EnvironmentFile=/etc/vulnshield/agent.env
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now vulnshield-agent
```

### Windows Server

1. Copy `agents/windows/` to the target server
2. Open PowerShell as Administrator
3. Run:

```powershell
Set-ExecutionPolicy Bypass -Scope Process
.\install.ps1 -ApiUrl "https://your-platform:8080/api/v1" -ApiToken "<token>"
```

4. Verify the scheduled task is running:

```powershell
Get-ScheduledTask -TaskName VulnShieldAgent
```

## Step 8: Configure LDAP (Optional)

For enterprise SSO, enable LDAP in `.env`:

```bash
LDAP_ENABLED=true
LDAP_SERVER=ldap://ldap.corp.local:389
LDAP_BASE_DN=dc=corp,dc=local
LDAP_BIND_DN=cn=vulnshield,ou=services,dc=corp,dc=local
LDAP_BIND_PASSWORD=ldap-bind-password
```

Restart auth-service:

```bash
docker compose up -d auth-service
```

## Step 9: Generate Agent Registration Token

1. Log in to the admin console as administrator
2. Navigate to **Settings → Agents → Registration Tokens**
3. Create a new token with appropriate scope (Linux, Windows, or both)
4. Use this token as `VULNSHIELD_API_TOKEN` in agent configuration

## Step 10: Enable mTLS (Production)

1. Generate a CA and client certificates:

```bash
mkdir -p certs && cd certs
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -subj "/CN=VulnShield CA"
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=agent-hostname"
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt
```

2. Deploy certificates to agents at `/etc/vulnshield/certs/` (Linux) or `C:\ProgramData\VulnShield\certs\` (Windows)
3. Set `VULNSHIELD_MTLS_ENABLED=true` in agent configuration
4. Configure the API Gateway to validate client certificates

## Post-Installation Checklist

- [ ] Default admin password changed
- [ ] JWT secret and database passwords rotated from defaults
- [ ] Agent registration tokens created
- [ ] At least one endpoint agent installed and showing online
- [ ] SMTP/Slack notifications configured and tested
- [ ] Database backup schedule configured
- [ ] Firewall rules applied (only required ports exposed)
- [ ] LDAP/MFA enabled if required by security policy

## Uninstallation

```bash
# Stop and remove all containers and volumes
make clean

# Remove agent (Linux)
sudo systemctl stop vulnshield-agent
sudo systemctl disable vulnshield-agent
sudo rm -rf /opt/vulnshield-agent /etc/vulnshield
sudo rm /etc/systemd/system/vulnshield-agent.service

# Remove agent (Windows)
Unregister-ScheduledTask -TaskName VulnShieldAgent -Confirm:$false
Remove-Item -Recurse -Force "C:\Program Files\VulnShield", "C:\ProgramData\VulnShield"
```
