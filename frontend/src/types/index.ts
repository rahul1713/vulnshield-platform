// ============================================================
// Enums & shared types matching backend schema
// ============================================================

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type VulnStatus =
  | 'open'
  | 'acknowledged'
  | 'assigned'
  | 'in_progress'
  | 'risk_accepted'
  | 'mitigated'
  | 'resolved'
  | 'closed'
  | 'reopened'
  | 'false_positive';

export type AssetType =
  | 'linux_server'
  | 'windows_server'
  | 'docker_container'
  | 'virtual_machine'
  | 'cloud_asset'
  | 'ip_range'
  | 'domain'
  | 'web_application'
  | 'network_device'
  | 'database';

export type AssetStatus = 'active' | 'inactive' | 'decommissioned' | 'pending_discovery';

export type ScanType =
  | 'agent'
  | 'agentless_ssh'
  | 'agentless_winrm'
  | 'agentless_smb'
  | 'network'
  | 'web_app'
  | 'cis_benchmark'
  | 'code_review'
  | 'red_team';

export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled' | 'partial';

export type ReportFormat = 'pdf' | 'excel' | 'csv' | 'json';
export type ReportType =
  | 'executive'
  | 'technical'
  | 'compliance'
  | 'patch'
  | 'risk'
  | 'trending'
  | 'asset';

export type UserRole =
  | 'administrator'
  | 'security_manager'
  | 'soc_analyst'
  | 'developer'
  | 'auditor'
  | 'read_only';

// ============================================================
// Auth
// ============================================================

export interface User {
  id: string;
  email: string;
  username: string;
  first_name?: string;
  last_name?: string;
  role: UserRole;
  permissions: string[];
  is_active: boolean;
  is_mfa_enabled?: boolean;
  last_login?: string;
  created_at?: string;
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  user: User;
}

export interface TokenPayload {
  sub: string;
  email: string;
  role: string;
  permissions: string[];
  exp: number;
  type: 'access' | 'refresh';
}

// ============================================================
// API pagination
// ============================================================

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface ListParams {
  page?: number;
  page_size?: number;
  sort_by?: string;
  sort_order?: 'asc' | 'desc';
  search?: string;
  [key: string]: string | number | undefined;
}

// ============================================================
// Domain entities
// ============================================================

export interface Role {
  id: string;
  name: string;
  description?: string;
  permissions: string[];
  created_at: string;
}

export interface Asset {
  id: string;
  name: string;
  asset_type: AssetType;
  status: AssetStatus;
  ip_address?: string;
  hostname?: string;
  fqdn?: string;
  os_family?: string;
  os_version?: string;
  criticality: number;
  business_unit?: string;
  owner_id?: string;
  tags: string[];
  last_seen?: string;
  vulnerability_count?: number;
  risk_score?: number;
  created_at: string;
  updated_at: string;
}

export interface CVE {
  id: string;
  cve_id: string;
  description?: string;
  cvss_v3_score?: number;
  cvss_v3_vector?: string;
  epss_score?: number;
  is_kev: boolean;
  published_date?: string;
}

export interface Vulnerability {
  id: string;
  asset_id: string;
  asset_name?: string;
  scan_id?: string;
  cve_identifier?: string;
  title: string;
  description?: string;
  severity: Severity;
  cvss_score?: number;
  epss_score?: number;
  status: VulnStatus;
  category?: string;
  affected_software?: string;
  affected_version?: string;
  remediation?: string;
  owner_id?: string;
  assigned_to?: string;
  due_date?: string;
  risk_score?: number;
  exploit_available: boolean;
  patch_available: boolean;
  first_detected: string;
  last_detected: string;
  resolved_at?: string;
}

export interface Scan {
  id: string;
  name: string;
  scan_type: ScanType;
  status: ScanStatus;
  target_asset_id?: string;
  target_asset_name?: string;
  started_at?: string;
  completed_at?: string;
  duration_seconds?: number;
  findings_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  created_by?: string;
  created_at: string;
}

export interface WebScanFinding {
  id: string;
  scan_id: string;
  url: string;
  vulnerability_type: string;
  owasp_category?: string;
  severity: Severity;
  title: string;
  description?: string;
  created_at: string;
}

export interface CodeReview {
  id: string;
  repository_url?: string;
  branch: string;
  language?: string;
  status: ScanStatus;
  findings_count: number;
  created_by?: string;
  started_at?: string;
  completed_at?: string;
  created_at: string;
}

export interface RedTeamCampaign {
  id: string;
  name: string;
  description?: string;
  status: ScanStatus;
  findings_count: number;
  created_by?: string;
  started_at?: string;
  completed_at?: string;
  executive_summary?: string;
  created_at: string;
}

export interface ComplianceFramework {
  id: string;
  name: string;
  version?: string;
  description?: string;
}

export interface ComplianceAssessment {
  id: string;
  asset_id?: string;
  framework_id: string;
  framework_name?: string;
  score?: number;
  passed_controls: number;
  failed_controls: number;
  total_controls: number;
  assessed_at: string;
}

export interface Report {
  id: string;
  name: string;
  report_type: ReportType;
  format: ReportFormat;
  status: ScanStatus;
  generated_by?: string;
  generated_at?: string;
  created_at: string;
}

export interface PatchInfo {
  id: string;
  vulnerability_id?: string;
  cve_id?: string;
  cve_identifier?: string;
  patch_available: boolean;
  patch_id?: string;
  patch_title?: string;
  patch_severity?: Severity;
  patch_release_date?: string;
  patch_download_url?: string;
  vendor_advisory_url?: string;
  workaround?: string;
  eol_status: boolean;
}

export interface RiskScore {
  id: string;
  entity_type: string;
  entity_id: string;
  entity_name?: string;
  technical_risk?: number;
  business_risk?: number;
  overall_score?: number;
  calculated_at: string;
}

export interface AuditLog {
  id: string;
  user_id?: string;
  user_email?: string;
  action: string;
  resource_type?: string;
  resource_id?: string;
  details?: Record<string, unknown>;
  ip_address?: string;
  created_at: string;
}

// ============================================================
// Dashboard analytics
// ============================================================

export interface DashboardStats {
  total_assets: number;
  total_vulnerabilities: number;
  critical_vulnerabilities: number;
  high_vulnerabilities: number;
  open_vulnerabilities: number;
  resolved_this_month: number;
  active_scans: number;
  compliance_score: number;
  mean_time_to_remediate_days: number;
  risk_score: number;
}

export interface SeverityDistribution {
  severity: Severity;
  count: number;
}

export interface RiskTrendPoint {
  date: string;
  critical: number;
  high: number;
  medium: number;
  overall_risk: number;
}

export interface RemediationProgress {
  month: string;
  opened: number;
  resolved: number;
}

export interface HeatmapCell {
  asset: string;
  category: string;
  value: number;
}

export interface ComplianceScorePoint {
  framework: string;
  score: number;
}

export interface SearchResult {
  type: 'asset' | 'vulnerability' | 'scan' | 'cve' | 'user';
  id: string;
  title: string;
  subtitle?: string;
  href: string;
}

export interface DashboardData {
  stats: DashboardStats;
  severity_distribution: SeverityDistribution[];
  risk_trends: RiskTrendPoint[];
  remediation_progress: RemediationProgress[];
  risk_heatmap: HeatmapCell[];
  compliance_scores: ComplianceScorePoint[];
}
