-- VulnShield Platform - Core Database Schema
-- PostgreSQL 16+

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================
-- RBAC & Authentication
-- ============================================================

CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(50) NOT NULL UNIQUE,
    description TEXT,
    permissions JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) NOT NULL UNIQUE,
    username VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    role_id UUID NOT NULL REFERENCES roles(id),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    is_mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_secret VARCHAR(255),
    last_login TIMESTAMPTZ,
    failed_login_attempts INT NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    password_changed_at TIMESTAMPTZ,
    must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
    ldap_dn VARCHAR(500),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_agent TEXT,
    ip_address INET
);

CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100),
    resource_id UUID,
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_created ON audit_logs(created_at DESC);

-- ============================================================
-- Asset Management
-- ============================================================

CREATE TYPE asset_type AS ENUM (
    'linux_server', 'windows_server', 'docker_container', 'virtual_machine',
    'cloud_asset', 'ip_range', 'domain', 'web_application', 'network_device', 'database'
);

CREATE TYPE asset_status AS ENUM ('active', 'inactive', 'decommissioned', 'pending_discovery');

CREATE TABLE assets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    asset_type asset_type NOT NULL,
    status asset_status NOT NULL DEFAULT 'active',
    ip_address INET,
    hostname VARCHAR(255),
    fqdn VARCHAR(500),
    mac_address MACADDR,
    os_family VARCHAR(50),
    os_version VARCHAR(100),
    kernel_version VARCHAR(100),
    cloud_provider VARCHAR(50),
    cloud_region VARCHAR(100),
    cloud_account_id VARCHAR(100),
    criticality INT NOT NULL DEFAULT 3 CHECK (criticality BETWEEN 1 AND 5),
    business_unit VARCHAR(100),
    owner_id UUID REFERENCES users(id),
    tags JSONB DEFAULT '[]',
    metadata JSONB DEFAULT '{}',
    last_seen TIMESTAMPTZ,
    discovered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE asset_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    change_type VARCHAR(50) NOT NULL,
    old_values JSONB,
    new_values JSONB,
    changed_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE asset_software (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    version VARCHAR(100),
    vendor VARCHAR(255),
    cpe VARCHAR(500),
    install_path TEXT,
    package_manager VARCHAR(50),
    is_running BOOLEAN DEFAULT FALSE,
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(asset_id, name, version)
);

CREATE TABLE asset_ports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    port INT NOT NULL,
    protocol VARCHAR(10) NOT NULL DEFAULT 'tcp',
    service_name VARCHAR(100),
    service_version VARCHAR(100),
    state VARCHAR(20) DEFAULT 'open',
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(asset_id, port, protocol)
);

CREATE INDEX idx_assets_ip ON assets(ip_address);
CREATE INDEX idx_assets_hostname ON assets(hostname);
CREATE INDEX idx_assets_type ON assets(asset_type);
CREATE INDEX idx_assets_criticality ON assets(criticality);

-- ============================================================
-- Agents
-- ============================================================

CREATE TYPE agent_status AS ENUM ('online', 'offline', 'pending', 'error');

CREATE TABLE agents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID REFERENCES assets(id),
    agent_id VARCHAR(100) NOT NULL UNIQUE,
    hostname VARCHAR(255),
    platform VARCHAR(50) NOT NULL,
    version VARCHAR(50),
    status agent_status NOT NULL DEFAULT 'pending',
    certificate_fingerprint VARCHAR(128),
    last_heartbeat TIMESTAMPTZ,
    ip_address INET,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- Vulnerability Intelligence
-- ============================================================

CREATE TABLE cves (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    cve_id VARCHAR(20) NOT NULL UNIQUE,
    description TEXT,
    cvss_v3_score DECIMAL(3,1),
    cvss_v3_vector VARCHAR(100),
    cvss_v2_score DECIMAL(3,1),
    epss_score DECIMAL(5,4),
    epss_percentile DECIMAL(5,4),
    is_kev BOOLEAN NOT NULL DEFAULT FALSE,
    kev_due_date DATE,
    published_date DATE,
    last_modified DATE,
    cwe_ids JSONB DEFAULT '[]',
    references JSONB DEFAULT '[]',
    cpes JSONB DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_cves_cve_id ON cves(cve_id);
CREATE INDEX idx_cves_cvss ON cves(cvss_v3_score DESC);
CREATE INDEX idx_cves_kev ON cves(is_kev) WHERE is_kev = TRUE;

-- ============================================================
-- Scans
-- ============================================================

CREATE TYPE scan_type AS ENUM (
    'agent', 'agentless_ssh', 'agentless_winrm', 'agentless_smb',
    'network', 'web_app', 'cis_benchmark', 'code_review', 'red_team'
);

CREATE TYPE scan_status AS ENUM (
    'queued', 'running', 'completed', 'failed', 'cancelled', 'partial'
);

CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    scan_type scan_type NOT NULL,
    status scan_status NOT NULL DEFAULT 'queued',
    target_asset_id UUID REFERENCES assets(id),
    target_config JSONB NOT NULL DEFAULT '{}',
    schedule_cron VARCHAR(100),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    duration_seconds INT,
    findings_count INT DEFAULT 0,
    critical_count INT DEFAULT 0,
    high_count INT DEFAULT 0,
    medium_count INT DEFAULT 0,
    low_count INT DEFAULT 0,
    info_count INT DEFAULT 0,
    created_by UUID REFERENCES users(id),
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE scan_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    asset_id UUID REFERENCES assets(id),
    raw_data JSONB,
    processed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- Vulnerabilities & Lifecycle
-- ============================================================

CREATE TYPE severity AS ENUM ('critical', 'high', 'medium', 'low', 'info');
CREATE TYPE vuln_status AS ENUM (
    'open', 'acknowledged', 'assigned', 'in_progress', 'risk_accepted',
    'mitigated', 'resolved', 'closed', 'reopened', 'false_positive'
);

CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    scan_id UUID REFERENCES scans(id),
    cve_id UUID REFERENCES cves(id),
    cve_identifier VARCHAR(20),
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity severity NOT NULL,
    cvss_score DECIMAL(3,1),
    epss_score DECIMAL(5,4),
    status vuln_status NOT NULL DEFAULT 'open',
    category VARCHAR(100),
    affected_software VARCHAR(255),
    affected_version VARCHAR(100),
    port INT,
    protocol VARCHAR(10),
    proof TEXT,
    remediation TEXT,
    workaround TEXT,
    owner_id UUID REFERENCES users(id),
    assigned_to UUID REFERENCES users(id),
    due_date DATE,
    sla_deadline TIMESTAMPTZ,
    risk_score DECIMAL(5,2),
    business_risk_score DECIMAL(5,2),
    exploit_available BOOLEAN DEFAULT FALSE,
    patch_available BOOLEAN DEFAULT FALSE,
    first_detected TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_detected TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE vulnerability_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    vulnerability_id UUID NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    old_status vuln_status,
    new_status vuln_status NOT NULL,
    changed_by UUID REFERENCES users(id),
    comment TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE vulnerability_comments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    vulnerability_id UUID NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id),
    content TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE vulnerability_evidence (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    vulnerability_id UUID NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    file_name VARCHAR(255) NOT NULL,
    file_path TEXT NOT NULL,
    file_type VARCHAR(50),
    file_size BIGINT,
    uploaded_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_vulns_asset ON vulnerabilities(asset_id);
CREATE INDEX idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulns_status ON vulnerabilities(status);
CREATE INDEX idx_vulns_cve ON vulnerabilities(cve_identifier);

-- ============================================================
-- Patch Intelligence
-- ============================================================

CREATE TABLE patch_information (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    vulnerability_id UUID REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    cve_id UUID REFERENCES cves(id),
    patch_available BOOLEAN NOT NULL DEFAULT FALSE,
    patch_id VARCHAR(100),
    patch_title VARCHAR(500),
    patch_severity severity,
    patch_release_date DATE,
    patch_download_url TEXT,
    vendor_advisory_url TEXT,
    workaround TEXT,
    compensating_controls TEXT,
    eol_status BOOLEAN DEFAULT FALSE,
    eol_date DATE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- Risk Scoring
-- ============================================================

CREATE TABLE risk_scores (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    entity_type VARCHAR(50) NOT NULL,
    entity_id UUID NOT NULL,
    technical_risk DECIMAL(5,2),
    business_risk DECIMAL(5,2),
    likelihood DECIMAL(5,2),
    impact DECIMAL(5,2),
    exploitability DECIMAL(5,2),
    exposure DECIMAL(5,2),
    overall_score DECIMAL(5,2),
    factors JSONB DEFAULT '{}',
    calculated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_risk_entity ON risk_scores(entity_type, entity_id);

-- ============================================================
-- Compliance
-- ============================================================

CREATE TABLE compliance_frameworks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL UNIQUE,
    version VARCHAR(50),
    description TEXT,
    controls JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE compliance_assessments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID REFERENCES assets(id),
    framework_id UUID NOT NULL REFERENCES compliance_frameworks(id),
    score DECIMAL(5,2),
    passed_controls INT DEFAULT 0,
    failed_controls INT DEFAULT 0,
    total_controls INT DEFAULT 0,
    results JSONB DEFAULT '[]',
    assessed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE cis_benchmark_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    benchmark_name VARCHAR(100) NOT NULL,
    platform VARCHAR(50) NOT NULL,
    score DECIMAL(5,2),
    passed INT DEFAULT 0,
    failed INT DEFAULT 0,
    total INT DEFAULT 0,
    results JSONB DEFAULT '[]',
    assessed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- AI Code Review
-- ============================================================

CREATE TABLE code_reviews (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    repository_url TEXT,
    branch VARCHAR(255) DEFAULT 'main',
    language VARCHAR(50),
    status scan_status NOT NULL DEFAULT 'queued',
    findings_count INT DEFAULT 0,
    created_by UUID REFERENCES users(id),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE code_review_findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    review_id UUID NOT NULL REFERENCES code_reviews(id) ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    function_name VARCHAR(255),
    line_start INT,
    line_end INT,
    severity severity NOT NULL,
    category VARCHAR(100),
    title VARCHAR(500) NOT NULL,
    description TEXT,
    root_cause TEXT,
    risk_description TEXT,
    cvss_score DECIMAL(3,1),
    code_snippet TEXT,
    recommended_fix TEXT,
    secure_code_example TEXT,
    references JSONB DEFAULT '[]',
    confidence_score DECIMAL(3,2),
    owasp_category VARCHAR(100),
    cwe_id VARCHAR(20),
    status vuln_status NOT NULL DEFAULT 'open',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- AI Red Team
-- ============================================================

CREATE TABLE red_team_campaigns (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    status scan_status NOT NULL DEFAULT 'queued',
    scope JSONB NOT NULL DEFAULT '{}',
    attack_chains JSONB DEFAULT '[]',
    mitre_mappings JSONB DEFAULT '[]',
    findings_count INT DEFAULT 0,
    created_by UUID REFERENCES users(id),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    executive_summary TEXT,
    findings_simulated BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE red_team_findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    campaign_id UUID NOT NULL REFERENCES red_team_campaigns(id) ON DELETE CASCADE,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity severity NOT NULL,
    attack_phase VARCHAR(100),
    mitre_technique_id VARCHAR(20),
    mitre_tactic VARCHAR(100),
    owasp_category VARCHAR(100),
    kill_chain_phase VARCHAR(100),
    proof TEXT,
    remediation TEXT,
    attack_chain_step INT,
    is_simulated BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- Reports & Notifications
-- ============================================================

CREATE TYPE report_format AS ENUM ('pdf', 'excel', 'csv', 'json');
CREATE TYPE report_type AS ENUM (
    'executive', 'technical', 'compliance', 'patch', 'risk', 'trending', 'asset'
);

CREATE TABLE reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    report_type report_type NOT NULL,
    format report_format NOT NULL,
    parameters JSONB DEFAULT '{}',
    file_path TEXT,
    status scan_status NOT NULL DEFAULT 'queued',
    generated_by UUID REFERENCES users(id),
    generated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TYPE notification_channel AS ENUM ('email', 'slack', 'teams', 'webhook');

CREATE TABLE notifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    channel notification_channel NOT NULL,
    recipient VARCHAR(255) NOT NULL,
    subject VARCHAR(500),
    message TEXT NOT NULL,
    payload JSONB,
    sent BOOLEAN NOT NULL DEFAULT FALSE,
    sent_at TIMESTAMPTZ,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE notification_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    severity_threshold severity,
    channels JSONB NOT NULL DEFAULT '[]',
    recipients JSONB NOT NULL DEFAULT '[]',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- Knowledge Base
-- ============================================================

CREATE TABLE knowledge_base (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title VARCHAR(500) NOT NULL,
    category VARCHAR(100),
    content TEXT NOT NULL,
    tags JSONB DEFAULT '[]',
    cve_ids JSONB DEFAULT '[]',
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- Web Application Scan Results
-- ============================================================

CREATE TABLE web_scan_findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    parameter VARCHAR(255),
    method VARCHAR(10),
    vulnerability_type VARCHAR(100) NOT NULL,
    owasp_category VARCHAR(100),
    severity severity NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    proof TEXT,
    request TEXT,
    response TEXT,
    remediation TEXT,
    cwe_id VARCHAR(20),
    is_simulated BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Updated_at trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_roles_updated_at BEFORE UPDATE ON roles FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_assets_updated_at BEFORE UPDATE ON assets FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_agents_updated_at BEFORE UPDATE ON agents FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_scans_updated_at BEFORE UPDATE ON scans FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_vulnerabilities_updated_at BEFORE UPDATE ON vulnerabilities FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
