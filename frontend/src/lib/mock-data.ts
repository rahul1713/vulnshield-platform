import {
  Asset,
  AuditLog,
  CodeReview,
  ComplianceAssessment,
  DashboardData,
  PaginatedResponse,
  PatchInfo,
  RedTeamCampaign,
  Report,
  RiskScore,
  Scan,
  SearchResult,
  User,
  Vulnerability,
  WebScanFinding,
} from '@/types';

export const MOCK_DASHBOARD: DashboardData = {
  stats: {
    total_assets: 847,
    total_vulnerabilities: 2341,
    critical_vulnerabilities: 47,
    high_vulnerabilities: 312,
    open_vulnerabilities: 1893,
    resolved_this_month: 156,
    active_scans: 8,
    compliance_score: 78.5,
    mean_time_to_remediate_days: 14.2,
    risk_score: 72.4,
  },
  severity_distribution: [
    { severity: 'critical', count: 47 },
    { severity: 'high', count: 312 },
    { severity: 'medium', count: 891 },
    { severity: 'low', count: 982 },
    { severity: 'info', count: 109 },
  ],
  risk_trends: [
    { date: 'Jan', critical: 52, high: 340, medium: 920, overall_risk: 78 },
    { date: 'Feb', critical: 48, high: 325, medium: 905, overall_risk: 76 },
    { date: 'Mar', critical: 45, high: 318, medium: 898, overall_risk: 75 },
    { date: 'Apr', critical: 47, high: 312, medium: 891, overall_risk: 72 },
    { date: 'May', critical: 44, high: 305, medium: 885, overall_risk: 71 },
    { date: 'Jun', critical: 47, high: 312, medium: 891, overall_risk: 72 },
  ],
  remediation_progress: [
    { month: 'Jan', opened: 245, resolved: 198 },
    { month: 'Feb', opened: 210, resolved: 225 },
    { month: 'Mar', opened: 189, resolved: 201 },
    { month: 'Apr', opened: 167, resolved: 178 },
    { month: 'May', opened: 145, resolved: 162 },
    { month: 'Jun', opened: 132, resolved: 156 },
  ],
  risk_heatmap: [
    { asset: 'prod-web-01', category: 'RCE', value: 95 },
    { asset: 'prod-web-01', category: 'Misconfig', value: 42 },
    { asset: 'prod-db-01', category: 'Auth', value: 65 },
    { asset: 'win-dc-01', category: 'RCE', value: 88 },
    { asset: 'dev-app-01', category: 'RCE', value: 98 },
    { asset: 'corp-portal', category: 'XSS', value: 72 },
    { asset: 'k8s-worker-01', category: 'Container', value: 55 },
    { asset: 'legacy-app-01', category: 'EOL', value: 70 },
  ],
  compliance_scores: [
    { framework: 'CIS Controls', score: 82 },
    { framework: 'NIST CSF', score: 76 },
    { framework: 'PCI DSS', score: 71 },
    { framework: 'ISO 27001', score: 84 },
    { framework: 'SOC 2', score: 79 },
  ],
};

export const MOCK_ASSETS: Asset[] = [
  { id: '1', name: 'prod-web-01', asset_type: 'linux_server', status: 'active', ip_address: '10.0.1.10', hostname: 'prod-web-01.corp.local', os_family: 'Linux', os_version: 'Ubuntu 22.04', criticality: 5, business_unit: 'Engineering', tags: ['production'], vulnerability_count: 12, risk_score: 85.5, created_at: '2024-01-15T00:00:00Z', updated_at: '2024-06-01T00:00:00Z' },
  { id: '2', name: 'prod-db-01', asset_type: 'linux_server', status: 'active', ip_address: '10.0.1.20', hostname: 'prod-db-01.corp.local', os_family: 'Linux', os_version: 'RHEL 9.2', criticality: 5, business_unit: 'Engineering', tags: ['production', 'pci'], vulnerability_count: 8, risk_score: 72.3, created_at: '2024-01-15T00:00:00Z', updated_at: '2024-06-01T00:00:00Z' },
  { id: '3', name: 'win-dc-01', asset_type: 'windows_server', status: 'active', ip_address: '10.0.2.10', hostname: 'win-dc-01.corp.local', os_family: 'Windows', os_version: 'Server 2022', criticality: 5, business_unit: 'IT', tags: ['critical'], vulnerability_count: 15, risk_score: 95.2, created_at: '2024-01-15T00:00:00Z', updated_at: '2024-06-01T00:00:00Z' },
  { id: '4', name: 'dev-app-01', asset_type: 'linux_server', status: 'active', ip_address: '10.0.3.10', hostname: 'dev-app-01.corp.local', os_family: 'Linux', os_version: 'Debian 12', criticality: 3, business_unit: 'Engineering', tags: ['development'], vulnerability_count: 22, risk_score: 98.7, created_at: '2024-02-01T00:00:00Z', updated_at: '2024-06-01T00:00:00Z' },
  { id: '5', name: 'corp-portal', asset_type: 'web_application', status: 'active', ip_address: '10.0.1.100', hostname: 'portal.corp.local', criticality: 4, business_unit: 'Marketing', tags: ['customer-facing'], vulnerability_count: 6, risk_score: 38.5, created_at: '2024-03-01T00:00:00Z', updated_at: '2024-06-01T00:00:00Z' },
];

export const MOCK_VULNERABILITIES: Vulnerability[] = [
  { id: '1', asset_id: '1', asset_name: 'prod-web-01', cve_identifier: 'CVE-2023-44487', title: 'HTTP/2 Rapid Reset Attack', severity: 'high', cvss_score: 7.5, status: 'open', category: 'denial_of_service', affected_software: 'nginx', affected_version: '1.18.0', exploit_available: true, patch_available: true, risk_score: 85.5, first_detected: '2024-03-15T00:00:00Z', last_detected: '2024-06-01T00:00:00Z' },
  { id: '2', asset_id: '4', asset_name: 'dev-app-01', cve_identifier: 'CVE-2021-44228', title: 'Log4Shell RCE', severity: 'critical', cvss_score: 10.0, status: 'in_progress', category: 'remote_code_execution', affected_software: 'log4j', affected_version: '2.14.1', exploit_available: true, patch_available: true, risk_score: 98.7, first_detected: '2024-01-10T00:00:00Z', last_detected: '2024-06-01T00:00:00Z' },
  { id: '3', asset_id: '3', asset_name: 'win-dc-01', cve_identifier: 'CVE-2024-21413', title: 'Outlook RCE', severity: 'critical', cvss_score: 9.8, status: 'open', category: 'remote_code_execution', affected_software: 'Microsoft Outlook', exploit_available: true, patch_available: true, risk_score: 95.2, first_detected: '2024-04-01T00:00:00Z', last_detected: '2024-06-01T00:00:00Z' },
  { id: '4', asset_id: '2', asset_name: 'prod-db-01', title: 'PostgreSQL Weak Authentication', severity: 'medium', cvss_score: 5.3, status: 'acknowledged', category: 'misconfiguration', affected_software: 'postgresql', exploit_available: false, patch_available: false, risk_score: 45.0, first_detected: '2024-02-20T00:00:00Z', last_detected: '2024-06-01T00:00:00Z' },
  { id: '5', asset_id: '1', asset_name: 'prod-web-01', title: 'Missing Security Headers', severity: 'medium', cvss_score: 4.3, status: 'open', category: 'misconfiguration', affected_software: 'nginx', exploit_available: false, patch_available: false, risk_score: 38.5, first_detected: '2024-05-01T00:00:00Z', last_detected: '2024-06-01T00:00:00Z' },
];

export const MOCK_SCANS: Scan[] = [
  { id: '1', name: 'Weekly Network Scan', scan_type: 'network', status: 'completed', findings_count: 45, critical_count: 2, high_count: 8, medium_count: 15, low_count: 20, info_count: 0, started_at: '2024-06-01T02:00:00Z', completed_at: '2024-06-01T04:30:00Z', duration_seconds: 9000, created_at: '2024-06-01T02:00:00Z' },
  { id: '2', name: 'Production Agent Scan', scan_type: 'agent', status: 'running', findings_count: 12, critical_count: 1, high_count: 3, medium_count: 5, low_count: 3, info_count: 0, started_at: '2024-06-05T10:00:00Z', created_at: '2024-06-05T10:00:00Z' },
  { id: '3', name: 'Web App DAST', scan_type: 'web_app', status: 'queued', findings_count: 0, critical_count: 0, high_count: 0, medium_count: 0, low_count: 0, info_count: 0, created_at: '2024-06-05T12:00:00Z' },
];

export function paginate<T>(items: T[], page = 1, pageSize = 10): PaginatedResponse<T> {
  const start = (page - 1) * pageSize;
  const paginatedItems = items.slice(start, start + pageSize);
  return {
    items: paginatedItems,
    total: items.length,
    page,
    page_size: pageSize,
    total_pages: Math.ceil(items.length / pageSize),
  };
}

export const MOCK_SEARCH: SearchResult[] = [
  { type: 'vulnerability', id: '2', title: 'Log4Shell RCE', subtitle: 'CVE-2021-44228 · dev-app-01', href: '/vulnerabilities' },
  { type: 'asset', id: '1', title: 'prod-web-01', subtitle: '10.0.1.10 · Linux', href: '/assets' },
  { type: 'cve', id: 'cve-1', title: 'CVE-2024-3400', subtitle: 'Palo Alto PAN-OS Command Injection', href: '/vulnerabilities' },
];

export const MOCK_USERS: User[] = [
  { id: '1', email: 'admin@vulnshield.local', username: 'admin', first_name: 'System', last_name: 'Administrator', role: 'administrator', permissions: ['*'], is_active: true, last_login: '2024-06-05T08:00:00Z' },
  { id: '2', email: 'soc@vulnshield.local', username: 'soc_analyst', first_name: 'Jane', last_name: 'Smith', role: 'soc_analyst', permissions: ['assets:read', 'vulnerabilities:read', 'dashboard:read'], is_active: true },
];

export const MOCK_AUDIT_LOGS: AuditLog[] = [
  { id: '1', user_email: 'admin@vulnshield.local', action: 'user.login', resource_type: 'user', ip_address: '192.168.1.100', created_at: '2024-06-05T08:00:00Z' },
  { id: '2', user_email: 'soc@vulnshield.local', action: 'vulnerability.update', resource_type: 'vulnerability', resource_id: '2', details: { status: 'in_progress' }, created_at: '2024-06-05T09:15:00Z' },
  { id: '3', user_email: 'admin@vulnshield.local', action: 'scan.create', resource_type: 'scan', resource_id: '3', created_at: '2024-06-05T12:00:00Z' },
];

export const MOCK_REPORTS: Report[] = [
  { id: '1', name: 'Executive Summary Q2', report_type: 'executive', format: 'pdf', status: 'completed', generated_at: '2024-06-01T00:00:00Z', created_at: '2024-06-01T00:00:00Z' },
  { id: '2', name: 'PCI Compliance Report', report_type: 'compliance', format: 'excel', status: 'completed', generated_at: '2024-05-15T00:00:00Z', created_at: '2024-05-15T00:00:00Z' },
];

export const MOCK_COMPLIANCE: ComplianceAssessment[] = [
  { id: '1', framework_id: '1', framework_name: 'CIS Controls v8', score: 82, passed_controls: 82, failed_controls: 18, total_controls: 100, assessed_at: '2024-06-01T00:00:00Z' },
  { id: '2', framework_id: '2', framework_name: 'NIST CSF 2.0', score: 76, passed_controls: 38, failed_controls: 12, total_controls: 50, assessed_at: '2024-06-01T00:00:00Z' },
];

export const MOCK_PATCHES: PatchInfo[] = [
  { id: '1', cve_identifier: 'CVE-2021-44228', patch_available: true, patch_title: 'Log4j 2.17.1 Security Update', patch_severity: 'critical', patch_release_date: '2021-12-17', eol_status: false },
  { id: '2', cve_identifier: 'CVE-2023-44487', patch_available: true, patch_title: 'nginx 1.25.3 HTTP/2 Fix', patch_severity: 'high', patch_release_date: '2023-10-24', eol_status: false },
];

export const MOCK_RISK: RiskScore[] = [
  { id: '1', entity_type: 'asset', entity_id: '4', entity_name: 'dev-app-01', technical_risk: 98.7, business_risk: 85.0, overall_score: 92.0, calculated_at: '2024-06-05T00:00:00Z' },
  { id: '2', entity_type: 'asset', entity_id: '3', entity_name: 'win-dc-01', technical_risk: 95.2, business_risk: 90.0, overall_score: 93.0, calculated_at: '2024-06-05T00:00:00Z' },
];

export const MOCK_CODE_REVIEWS: CodeReview[] = [
  { id: '1', repository_url: 'https://github.com/corp/payment-api', branch: 'main', language: 'Java', status: 'completed', findings_count: 7, started_at: '2024-06-03T00:00:00Z', completed_at: '2024-06-03T02:00:00Z', created_at: '2024-06-03T00:00:00Z' },
];

export const MOCK_RED_TEAM: RedTeamCampaign[] = [
  { id: '1', name: 'Q2 External Pen Test', description: 'Simulated external attacker campaign', status: 'completed', findings_count: 12, started_at: '2024-05-01T00:00:00Z', completed_at: '2024-05-15T00:00:00Z', created_at: '2024-05-01T00:00:00Z' },
];

export const MOCK_WEB_FINDINGS: WebScanFinding[] = [
  { id: '1', scan_id: '3', url: 'https://portal.corp.local/login', vulnerability_type: 'SQL Injection', owasp_category: 'A03:2021', severity: 'critical', title: 'SQL Injection in login form', created_at: '2024-06-01T00:00:00Z' },
  { id: '2', scan_id: '3', url: 'https://portal.corp.local/search', vulnerability_type: 'XSS', owasp_category: 'A03:2021', severity: 'high', title: 'Reflected XSS in search parameter', created_at: '2024-06-01T00:00:00Z' },
];
