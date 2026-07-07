# VulnShield User Manual

Guide for SOC analysts, developers, and security managers using the VulnShield dashboard.

![Dashboard overview](images/dashboard-overview.png)

## Getting Started

### Logging In

1. Navigate to your VulnShield instance (e.g., http://localhost:3000)
2. Enter your username and password (provided by your administrator)
3. If MFA is enabled, enter the TOTP code from your authenticator app
4. Change your password if prompted on first login

> Credentials are set via `INIT_ADMIN_PASSWORD` at deployment. There are no default passwords in production or sandbox builds.

### Dashboard Overview

The main dashboard provides an at-a-glance view of your security posture. Use **Quick Actions** to start scans or navigate to vulnerabilities.

![Operations workflow](images/operations-workflow.png)

- **Risk Score** — Composite score across all assets (0–100)
- **Open Vulnerabilities** — Breakdown by severity (Critical, High, Medium, Low)
- **Asset Coverage** — Total assets monitored vs. pending discovery
- **Recent Activity** — Latest scans, new vulnerabilities, status changes
- **Trending Chart** — Vulnerability count over the last 30 days

## Asset Management

### Viewing Assets

Navigate to **Assets** in the sidebar to see all discovered assets. Each asset card shows:

- Hostname, IP address, and OS
- Criticality rating (1–5 stars)
- Open vulnerability count by severity
- Last seen timestamp
- Tags (e.g., production, pci, internet-facing)

### Asset Details

Click an asset to view:

- **Overview** — OS info, kernel version, business unit, owner
- **Software Inventory** — Installed packages with versions and CPE identifiers
- **Open Ports** — Listening services with version detection
- **Vulnerabilities** — All findings for this asset
- **Compliance** — CIS benchmark and framework assessment results
- **History** — Change log for asset metadata

### Filtering and Search

Use the search bar to find assets by hostname, IP, or tag. Filter by:

- Asset type (Linux, Windows, Web Application, Cloud)
- Status (Active, Inactive, Decommissioned)
- Criticality level
- Business unit

## Vulnerability Management

### Vulnerability List

Navigate to **Vulnerabilities** to see all findings across your environment. The list supports:

- Sorting by severity, risk score, date, or SLA deadline
- Filtering by status, severity, asset, CVE, or assignee
- Bulk actions: assign, change status, export

### Vulnerability Detail

Each vulnerability shows:

| Field | Description |
|-------|-------------|
| Title | Finding name (CVE ID or descriptive title) |
| Severity | Critical, High, Medium, Low, Info |
| CVSS Score | Base CVSS v3 score |
| EPSS Score | Exploit Prediction Scoring System probability |
| Risk Score | VulnShield composite score (technical + business context) |
| Status | Current lifecycle state |
| Affected Software | Package name and version |
| Remediation | Recommended fix or patch |
| Proof | Evidence of the vulnerability |

### Vulnerability Lifecycle

```
Open → Acknowledged → Assigned → In Progress → Resolved → Closed
                  ↘ Risk Accepted
                  ↘ False Positive → Closed
                  ↘ Reopened (from Closed)
```

**Actions you can take:**

- **Acknowledge** — Confirm you've seen the finding
- **Assign** — Assign to a team member with a due date
- **Add Comment** — Document investigation notes
- **Upload Evidence** — Attach screenshots or log files
- **Accept Risk** — Document risk acceptance with justification
- **Mark False Positive** — Flag incorrect findings
- **Resolve** — Mark as fixed after remediation

### SLA Tracking

Vulnerabilities have SLA deadlines based on severity:

| Severity | Default SLA |
|----------|-------------|
| Critical | 7 days |
| High | 30 days |
| Medium | 90 days |
| Low | 180 days |

Overdue items appear highlighted in red on the dashboard.

## Scanning

### Launching a Scan

1. Go to **Scans → New Scan**
2. Select scan type:
   - **Agent** — Uses installed endpoint agents
   - **Network** — Port scan and service detection
   - **Web Application** — OWASP vulnerability testing
   - **CIS Benchmark** — Configuration compliance check
3. Choose target assets or IP ranges
4. Click **Start Scan**

### Monitoring Scan Progress

Active scans show real-time progress with finding counts updating as results arrive. Completed scans display a summary with severity breakdown.

### Scheduled Scans

Create recurring scans with cron expressions:

- Daily: `0 2 * * *` (2 AM every day)
- Weekly: `0 2 * * 1` (2 AM every Monday)
- Monthly: `0 2 1 * *` (2 AM on the 1st)

## AI Code Review

Navigate to **Code Review** to analyze source code repositories:

1. Click **New Review**
2. Enter repository URL and branch
3. Select programming language
4. Click **Start Review**

The AI engine analyzes code for OWASP Top 10 vulnerabilities, insecure patterns, and logic flaws. Each finding includes:

- File path and line numbers
- Severity and confidence score
- Root cause analysis
- Recommended fix with secure code example
- CWE and OWASP category mapping

## AI Red Team

Navigate to **Red Team** for AI-driven attack simulation:

1. Click **New Campaign**
2. Define scope (target assets, IP ranges, excluded systems)
3. Start the campaign

Results include:

- Attack chains with step-by-step execution
- MITRE ATT&CK technique mappings
- Kill chain phase identification
- Proof of exploitation
- Remediation recommendations
- Executive summary for leadership

## Reports

Navigate to **Reports** to generate and download reports:

| Report Type | Contents |
|-------------|----------|
| Executive | High-level risk summary for leadership |
| Technical | Detailed vulnerability listing with remediation |
| Compliance | Framework assessment results (CIS, NIST, ISO) |
| Patch | Available patches prioritized by risk |
| Risk | Risk score trends and top-risk assets |
| Trending | Vulnerability trends over time |
| Asset | Per-asset inventory and findings |

Export formats: PDF, Excel, CSV, JSON.

## Compliance

Navigate to **Compliance** to view framework assessments:

- CIS Controls v8
- NIST Cybersecurity Framework 2.0
- NIST 800-53 Rev 5
- ISO 27001:2022
- PCI-DSS 4.0

Each assessment shows pass/fail per control with linked vulnerabilities that cause failures.

## Notifications

Configure alert rules under **Settings → Notifications**:

- **Event types**: New critical vulnerability, SLA breach, scan completed, agent offline
- **Channels**: Email, Slack, Microsoft Teams, Webhook
- **Severity threshold**: Only alert on High and above

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `/` | Focus search bar |
| `g d` | Go to Dashboard |
| `g a` | Go to Assets |
| `g v` | Go to Vulnerabilities |
| `g s` | Go to Scans |
| `Esc` | Close modal/panel |

## Getting Help

- **Knowledge Base**: Built-in articles linked from vulnerability remediation steps
- **Administrator**: Contact your VulnShield admin for access issues
- **Documentation**: See `docs/ADMIN_MANUAL.md` for platform configuration
