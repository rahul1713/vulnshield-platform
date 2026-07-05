# VulnShield Administrator Manual

Guide for platform administrators managing VulnShield deployment, users, agents, and integrations.

## Administrator Responsibilities

- User and role management (RBAC)
- Agent deployment and certificate management
- Platform configuration and integrations
- Backup and disaster recovery
- Security hardening

## User Management

### Roles and Permissions

| Role | Permissions |
|------|------------|
| **administrator** | Full access (`*`) |
| **security_manager** | Assets, scans, vulnerabilities, reports, compliance, user read |
| **soc_analyst** | Assets read, scans, vulnerabilities, reports read, dashboard |
| **developer** | Assets read, vulnerabilities, code review |
| **auditor** | Read-only: assets, vulnerabilities, reports, compliance, audit logs |
| **read_only** | Dashboard, assets, vulnerabilities, reports (read only) |

### Creating Users

1. Navigate to **Admin → Users → Add User**
2. Fill in email, username, name, and role
3. Set temporary password (user must change on first login)
4. Optionally enable MFA

Via API:

```bash
curl -X POST http://localhost:8080/api/v1/users \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "analyst@corp.local",
    "username": "janalyst",
    "first_name": "Jane",
    "last_name": "Analyst",
    "role": "soc_analyst",
    "password": "TempPass@123456"
  }'
```

### Password Policy

Enforced by the auth service:

- Minimum 12 characters
- At least one uppercase, lowercase, digit, and special character
- Account lockout after 5 failed attempts (15-minute lockout)

### LDAP Integration

Enable in `.env`:

```bash
LDAP_ENABLED=true
LDAP_SERVER=ldap://ldap.corp.local:389
LDAP_BASE_DN=dc=corp,dc=local
LDAP_BIND_DN=cn=vulnshield,ou=services,dc=corp,dc=local
LDAP_BIND_PASSWORD=secret
```

LDAP users are mapped to VulnShield roles via group membership configured in the auth service.

### MFA Configuration

```bash
MFA_ENABLED=true
```

When enabled, users enroll TOTP via **Settings → Security → Enable MFA**. Recovery codes are generated at enrollment.

## Agent Management

### Registration Tokens

1. Go to **Admin → Agents → Registration Tokens**
2. Create a token with:
   - Name (e.g., "Production Linux Fleet")
   - Platform scope (Linux, Windows, or All)
   - Expiration date
   - Maximum agents allowed
3. Distribute the token to agent installers

### Monitoring Agents

The **Admin → Agents** page shows:

| Column | Description |
|--------|-------------|
| Agent ID | Unique identifier |
| Hostname | Registered hostname |
| Platform | linux / windows |
| Status | online, offline, pending, error |
| Last Heartbeat | Time since last check-in |
| Version | Agent software version |

Agents offline for more than 15 minutes trigger a notification if configured.

### mTLS Certificate Management

For production deployments, agents authenticate with client certificates:

1. **Generate CA** (once per environment):

```bash
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
  -subj "/CN=VulnShield CA/O=YourOrg"
```

2. **Issue agent certificates**:

```bash
openssl genrsa -out agent-hostname.key 2048
openssl req -new -key agent-hostname.key -out agent-hostname.csr \
  -subj "/CN=agent-hostname/O=YourOrg"
openssl x509 -req -days 365 -in agent-hostname.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial -out agent-hostname.crt
```

3. Deploy to agent: `client.crt`, `client.key`, `ca.crt`
4. Enable mTLS on both gateway and agent

### Revoking Agents

1. Select the agent in **Admin → Agents**
2. Click **Revoke**
3. The agent's certificate is added to the CRL and future heartbeats are rejected

## Platform Configuration

### Environment Variables

Critical settings in `.env`:

| Variable | Purpose | Production Guidance |
|----------|---------|-------------------|
| `JWT_SECRET` | Token signing key | 256-bit random hex |
| `POSTGRES_PASSWORD` | Database password | Strong, unique password |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | JWT lifetime | 15–30 minutes |
| `REFRESH_TOKEN_EXPIRE_DAYS` | Refresh token lifetime | 1–7 days |
| `LOG_LEVEL` | Logging verbosity | INFO or WARNING |

Restart affected services after changes:

```bash
docker compose up -d auth-service api-gateway
```

### LLM Provider Configuration

| Provider | Variables |
|----------|-----------|
| Ollama (local) | `LLM_PROVIDER=ollama`, `OLLAMA_BASE_URL`, `OLLAMA_MODEL` |
| OpenAI | `LLM_PROVIDER=openai`, `OPENAI_API_KEY`, `OPENAI_MODEL` |
| Anthropic | `LLM_PROVIDER=anthropic`, `ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL` |

### Notification Channels

#### Email (SMTP)

```bash
SMTP_HOST=smtp.corp.local
SMTP_PORT=587
SMTP_USER=alerts@corp.local
SMTP_PASSWORD=smtp-password
SMTP_FROM=noreply@vulnshield.corp.local
```

#### Slack

Create an Incoming Webhook in Slack and set:

```bash
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../xxx
```

#### Microsoft Teams

Create a Connector webhook and set:

```bash
TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/...
```

### Notification Rules

Configure in **Admin → Notifications → Rules**:

```json
{
  "name": "Critical Vulnerability Alert",
  "event_type": "vulnerability.created",
  "severity_threshold": "critical",
  "channels": ["email", "slack"],
  "recipients": ["soc-team@corp.local", "#security-alerts"]
}
```

## Database Administration

### Backup Schedule

Recommended daily backup via cron:

```bash
0 3 * * * docker compose -f /opt/vulnshield/docker-compose.yml exec -T postgres \
  pg_dump -U vulnshield vulnshield | gzip > /backup/vulnshield-$(date +\%Y\%m\%d).sql.gz
```

### Audit Logs

All user actions are recorded in the `audit_logs` table. Query via **Admin → Audit Logs** or API:

```bash
curl "http://localhost:8080/api/v1/audit-logs?action=login&limit=50" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

Retained indefinitely by default. Configure retention in compliance settings.

## Security Hardening

### Network

- Expose only ports 443 (HTTPS) and 3000 (frontend) externally
- Keep PostgreSQL (5432), Redis (6379), RabbitMQ (5672) on internal network only
- Use a reverse proxy (nginx/Traefik) for TLS termination

### Reverse Proxy Example (nginx)

```nginx
server {
    listen 443 ssl;
    server_name vulnshield.corp.local;

    ssl_certificate /etc/ssl/vulnshield.crt;
    ssl_certificate_key /etc/ssl/vulnshield.key;

    location /api/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
    }
}
```

### Security Checklist

- [ ] Change all default passwords and secrets
- [ ] Enable MFA for administrator accounts
- [ ] Configure mTLS for agent communication
- [ ] Restrict admin API to internal network
- [ ] Enable audit log monitoring
- [ ] Schedule automated backups with off-site storage
- [ ] Configure rate limiting on the API Gateway
- [ ] Review RBAC assignments quarterly
- [ ] Keep Docker images updated (`docker compose pull && make build`)

## Monitoring

### Service Health

```bash
# Check all containers
docker compose ps

# API health endpoint
curl http://localhost:8080/api/v1/health

# Database connectivity
docker compose exec postgres pg_isready -U vulnshield
```

### Log Aggregation

Forward Docker logs to your SIEM:

```bash
docker compose logs -f --no-color 2>&1 | your-log-shipper
```

## Troubleshooting

| Symptom | Diagnosis | Fix |
|---------|-----------|-----|
| Users can't log in | Check auth-service logs | Verify JWT_SECRET hasn't changed; check LDAP connectivity |
| Agents show offline | Check last heartbeat | Verify network path to gateway; check agent logs |
| Scans stuck in queued | Check RabbitMQ | Verify queue consumers are running; restart scanner-service |
| Reports fail to generate | Check MinIO | Verify bucket exists; check reporting-service logs |
| High memory usage | Check Ollama | Limit model size or use external LLM provider |
| Database disk full | Check volume size | Run VACUUM; archive old scan results |

## Upgrade Procedure

```bash
# Pull latest code
git pull origin main

# Rebuild images
make build

# Run migrations (if schema changed)
make migrate

# Rolling restart
docker compose up -d

# Verify
docker compose ps
curl http://localhost:8080/api/v1/health
```

Always back up the database before upgrading.
