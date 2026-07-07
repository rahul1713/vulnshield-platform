# VulnShield Documentation

Welcome to the VulnShield documentation hub. Start with the [README](../README.md) for deployment, then use the guides below for your role.

## Reference images

| Image | Description |
|-------|-------------|
| [architecture-overview.png](images/architecture-overview.png) | System architecture — frontend, gateway, microservices, data layer |
| [dashboard-overview.png](images/dashboard-overview.png) | Executive dashboard — stats, charts, quick actions |
| [operations-workflow.png](images/operations-workflow.png) | Security operations loop — discover through remediate |
| [deployment-flow.png](images/deployment-flow.png) | Sandbox deployment — secrets, compose, dashboard |

## Quick links by role

### I want to deploy VulnShield
1. **[Sandbox (recommended)](SANDBOX_DEPLOYMENT.md)** — Hardened, isolated, no data leakage
2. **[Docker Compose](DEPLOYMENT.md)** — Development and staging
3. **[Installation guide](INSTALLATION.md)** — Full server setup, agents, LDAP, mTLS
4. **Kubernetes** — `k8s/` manifests + [secrets.example.yaml](../k8s/secrets.example.yaml)

### I want to use the platform
- **[User Manual](USER_MANUAL.md)** — Dashboard, scans, vulnerabilities, reports
- **[Capabilities reference](CAPABILITIES.md)** — Every operation and what it does

### I want to administer the platform
- **[Admin Manual](ADMIN_MANUAL.md)** — Users, RBAC, agents, backups, integrations

### I want to extend or contribute
- **[Developer Guide](DEVELOPER.md)** — Services, shared libraries, agents, CI/CD
- **[Architecture](ARCHITECTURE.md)** — Design, data flows, service boundaries
- **[ER Diagram](ER_DIAGRAM.md)** — Database schema

## Deployment decision tree

```
Need isolated lab / POC / staging?
  └─ Yes → SANDBOX_DEPLOYMENT.md (make sandbox-env && make sandbox-up)

Need local development?
  └─ Yes → DEPLOYMENT.md (cp .env.example .env && make up)

Need production scale / HA?
  └─ Yes → INSTALLATION.md + k8s/ manifests
```

## Support

- Repository: https://github.com/rahul1713/vulnshield-platform
- Issues: https://github.com/rahul1713/vulnshield-platform/issues
