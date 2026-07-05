# VulnShield Platform Entity Relationship Diagram

This document describes the PostgreSQL schema used by all VulnShield microservices. The canonical schema is defined in `shared/database/init/001_schema.sql`.

## Core Entity Relationships

```mermaid
erDiagram
    roles ||--o{ users : "has"
    users ||--o{ refresh_tokens : "has"
    users ||--o{ audit_logs : "performs"
    users ||--o{ assets : "owns"
    users ||--o{ scans : "creates"
    users ||--o{ vulnerabilities : "assigned_to"
    users ||--o{ code_reviews : "creates"
    users ||--o{ red_team_campaigns : "creates"
    users ||--o{ reports : "generates"

    assets ||--o{ asset_history : "tracks"
    assets ||--o{ asset_software : "has"
    assets ||--o{ asset_ports : "exposes"
    assets ||--o{ agents : "monitored_by"
    assets ||--o{ scans : "targeted_by"
    assets ||--o{ vulnerabilities : "has"
    assets ||--o{ compliance_assessments : "assessed"
    assets ||--o{ cis_benchmark_results : "benchmarked"

    agents {
        uuid id PK
        uuid asset_id FK
        varchar agent_id UK
        varchar hostname
        varchar platform
        varchar version
        agent_status status
        varchar certificate_fingerprint
        timestamptz last_heartbeat
        inet ip_address
        jsonb metadata
    }

    cves ||--o{ vulnerabilities : "references"
    cves ||--o{ patch_information : "has_patch"

    scans ||--o{ scan_results : "produces"
    scans ||--o{ vulnerabilities : "discovers"
    scans ||--o{ web_scan_findings : "finds"

    vulnerabilities ||--o{ vulnerability_history : "tracks"
    vulnerabilities ||--o{ vulnerability_comments : "has"
    vulnerabilities ||--o{ vulnerability_evidence : "has"
    vulnerabilities ||--o{ patch_information : "needs"

    compliance_frameworks ||--o{ compliance_assessments : "assessed_against"

    code_reviews ||--o{ code_review_findings : "contains"

    red_team_campaigns ||--o{ red_team_findings : "contains"

    notification_rules ||--o{ notifications : "triggers"
```

## RBAC & Authentication

```mermaid
erDiagram
    roles {
        uuid id PK
        varchar name UK
        text description
        jsonb permissions
        timestamptz created_at
        timestamptz updated_at
    }

    users {
        uuid id PK
        varchar email UK
        varchar username UK
        varchar password_hash
        varchar first_name
        varchar last_name
        uuid role_id FK
        boolean is_active
        boolean is_mfa_enabled
        varchar mfa_secret
        timestamptz last_login
        int failed_login_attempts
        timestamptz locked_until
        varchar ldap_dn
    }

    refresh_tokens {
        uuid id PK
        uuid user_id FK
        varchar token_hash
        timestamptz expires_at
        boolean revoked
        text user_agent
        inet ip_address
    }

    audit_logs {
        uuid id PK
        uuid user_id FK
        varchar action
        varchar resource_type
        uuid resource_id
        jsonb details
        inet ip_address
        timestamptz created_at
    }
```

## Asset Management

```mermaid
erDiagram
    assets {
        uuid id PK
        varchar name
        asset_type asset_type
        asset_status status
        inet ip_address
        varchar hostname
        varchar fqdn
        macaddr mac_address
        varchar os_family
        varchar os_version
        varchar kernel_version
        int criticality
        varchar business_unit
        uuid owner_id FK
        jsonb tags
        jsonb metadata
        timestamptz last_seen
    }

    asset_software {
        uuid id PK
        uuid asset_id FK
        varchar name
        varchar version
        varchar vendor
        varchar cpe
        text install_path
        varchar package_manager
        boolean is_running
    }

    asset_ports {
        uuid id PK
        uuid asset_id FK
        int port
        varchar protocol
        varchar service_name
        varchar service_version
        varchar state
    }

    asset_history {
        uuid id PK
        uuid asset_id FK
        varchar change_type
        jsonb old_values
        jsonb new_values
        uuid changed_by FK
    }
```

## Vulnerability Lifecycle

```mermaid
erDiagram
    vulnerabilities {
        uuid id PK
        uuid asset_id FK
        uuid scan_id FK
        uuid cve_id FK
        varchar cve_identifier
        varchar title
        severity severity
        decimal cvss_score
        decimal epss_score
        vuln_status status
        varchar category
        varchar affected_software
        uuid assigned_to FK
        date due_date
        timestamptz sla_deadline
        decimal risk_score
        decimal business_risk_score
        boolean exploit_available
        boolean patch_available
        timestamptz first_detected
        timestamptz resolved_at
    }

    cves {
        uuid id PK
        varchar cve_id UK
        text description
        decimal cvss_v3_score
        varchar cvss_v3_vector
        decimal epss_score
        boolean is_kev
        date kev_due_date
        date published_date
        jsonb cwe_ids
        jsonb cpes
    }

    vulnerability_history {
        uuid id PK
        uuid vulnerability_id FK
        vuln_status old_status
        vuln_status new_status
        uuid changed_by FK
        text comment
    }

    patch_information {
        uuid id PK
        uuid vulnerability_id FK
        uuid cve_id FK
        boolean patch_available
        varchar patch_id
        varchar patch_title
        text patch_download_url
        text vendor_advisory_url
        boolean eol_status
        date eol_date
    }
```

## Scanning & AI

```mermaid
erDiagram
    scans {
        uuid id PK
        varchar name
        scan_type scan_type
        scan_status status
        uuid target_asset_id FK
        jsonb target_config
        varchar schedule_cron
        int findings_count
        int critical_count
        int high_count
        uuid created_by FK
    }

    code_reviews {
        uuid id PK
        text repository_url
        varchar branch
        varchar language
        scan_status status
        int findings_count
        uuid created_by FK
    }

    code_review_findings {
        uuid id PK
        uuid review_id FK
        text file_path
        int line_start
        severity severity
        varchar title
        text description
        text recommended_fix
        varchar owasp_category
        varchar cwe_id
    }

    red_team_campaigns {
        uuid id PK
        varchar name
        scan_status status
        jsonb scope
        jsonb attack_chains
        jsonb mitre_mappings
        text executive_summary
        uuid created_by FK
    }

    red_team_findings {
        uuid id PK
        uuid campaign_id FK
        varchar title
        severity severity
        varchar attack_phase
        varchar mitre_technique_id
        varchar mitre_tactic
        text proof
        text remediation
    }
```

## Key Enumerations

| Enum | Values |
|------|--------|
| `asset_type` | linux_server, windows_server, docker_container, virtual_machine, cloud_asset, ip_range, domain, web_application, network_device, database |
| `asset_status` | active, inactive, decommissioned, pending_discovery |
| `agent_status` | online, offline, pending, error |
| `scan_type` | agent, agentless_ssh, agentless_winrm, agentless_smb, network, web_app, cis_benchmark, code_review, red_team |
| `scan_status` | queued, running, completed, failed, cancelled, partial |
| `severity` | critical, high, medium, low, info |
| `vuln_status` | open, acknowledged, assigned, in_progress, risk_accepted, mitigated, resolved, closed, reopened, false_positive |
| `report_type` | executive, technical, compliance, patch, risk, trending, asset |
| `notification_channel` | email, slack, teams, webhook |

## Indexes

Performance-critical indexes are defined on:

- `assets(ip_address)`, `assets(hostname)`, `assets(criticality)`
- `vulnerabilities(asset_id)`, `vulnerabilities(severity)`, `vulnerabilities(status)`, `vulnerabilities(cve_identifier)`
- `cves(cve_id)`, `cves(cvss_v3_score DESC)`, `cves(is_kev) WHERE is_kev = TRUE`
- `audit_logs(user_id)`, `audit_logs(action)`, `audit_logs(created_at DESC)`
- `risk_scores(entity_type, entity_id)`
