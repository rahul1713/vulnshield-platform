-- VulnShield Platform - Bootstrap data (all environments)
-- Roles and reference frameworks required for a working deployment.
-- Fake corp.local sample assets/vulns are in shared/database/seed/ — run `make seed` in development only.

-- Roles with RBAC permissions (no default admin user — created via INIT_ADMIN_PASSWORD at auth-service startup)
INSERT INTO roles (id, name, description, permissions) VALUES
('a0000000-0000-0000-0000-000000000001', 'administrator', 'Full system access',
 '["*"]'),
('a0000000-0000-0000-0000-000000000002', 'security_manager', 'Manage security operations',
 '["assets:read","assets:write","scans:read","scans:write","vulnerabilities:read","vulnerabilities:write","reports:read","reports:write","compliance:read","compliance:write","dashboard:read","users:read"]'),
('a0000000-0000-0000-0000-000000000003', 'soc_analyst', 'SOC operations and triage',
 '["assets:read","scans:read","scans:write","vulnerabilities:read","vulnerabilities:write","reports:read","dashboard:read","redteam:read"]'),
('a0000000-0000-0000-0000-000000000004', 'developer', 'Code review and remediation',
 '["assets:read","vulnerabilities:read","vulnerabilities:write","codereview:read","codereview:write","dashboard:read"]'),
('a0000000-0000-0000-0000-000000000005', 'auditor', 'Audit and compliance review',
 '["assets:read","vulnerabilities:read","reports:read","compliance:read","audit:read","dashboard:read"]'),
('a0000000-0000-0000-0000-000000000006', 'read_only', 'Read-only access',
 '["assets:read","vulnerabilities:read","reports:read","dashboard:read"]');

-- Compliance frameworks (reference data)
INSERT INTO compliance_frameworks (id, name, version, description) VALUES
('d0000000-0000-0000-0000-000000000001', 'CIS Controls', 'v8', 'Center for Internet Security Critical Security Controls'),
('d0000000-0000-0000-0000-000000000002', 'NIST CSF', '2.0', 'NIST Cybersecurity Framework'),
('d0000000-0000-0000-0000-000000000003', 'NIST 800-53', 'Rev 5', 'NIST Special Publication 800-53'),
('d0000000-0000-0000-0000-000000000004', 'ISO 27001', '2022', 'Information Security Management'),
('d0000000-0000-0000-0000-000000000005', 'PCI DSS', '4.0', 'Payment Card Industry Data Security Standard'),
('d0000000-0000-0000-0000-000000000006', 'SOC 2', '2017', 'Service Organization Control 2'),
('d0000000-0000-0000-0000-000000000007', 'HIPAA', '2013', 'Health Insurance Portability and Accountability Act');
