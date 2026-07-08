-- VulnShield Platform - Development sample data (NOT loaded in sandbox/production)
-- Load manually: make seed

-- Sample CVEs
INSERT INTO cves (cve_id, description, cvss_v3_score, cvss_v3_vector, epss_score, is_kev, published_date, cwe_ids, cpes) VALUES
('CVE-2024-1086', 'Linux kernel use-after-free vulnerability in netfilter', 8.8, 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', div(0.042,1), TRUE, '2024-01-31', '["CWE-416"]', '["cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"]'),
('CVE-2023-44487', 'HTTP/2 Rapid Reset Attack', 7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 0.94312, TRUE, '2023-10-10', '["CWE-400"]', '["cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"]'),
('CVE-2024-21413', 'Microsoft Outlook Remote Code Execution', 9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', 0.87654, TRUE, '2024-02-13', '["CWE-20"]', '["cpe:2.3:a:microsoft:outlook:*:*:*:*:*:*:*:*"]'),
('CVE-2023-4966', 'Citrix Bleed - sensitive information disclosure', 9.4, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 0.97543, TRUE, '2023-10-10', '["CWE-119"]', '["cpe:2.3:a:citrix:netscaler:*:*:*:*:*:*:*:*"]'),
('CVE-2024-3400', 'Palo Alto PAN-OS Command Injection', 10.0, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 0.99876, TRUE, '2024-04-12', '["CWE-77"]', '["cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*"]'),
('CVE-2021-44228', 'Log4Shell - Apache Log4j2 RCE', 10.0, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 0.97555, TRUE, '2021-12-10', '["CWE-502","CWE-917"]', '["cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"]'),
('CVE-2023-22515', 'Atlassian Confluence Broken Access Control', 10.0, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 0.92341, TRUE, '2023-10-04', '["CWE-863"]', '["cpe:2.3:a:atlassian:confluence:*:*:*:*:*:*:*:*"]'),
('CVE-2024-21762', 'Fortinet FortiOS Out-of-bounds Write', 9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 0.91234, TRUE, '2024-02-08', '["CWE-787"]', '["cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*"]');

-- Sample Assets
INSERT INTO assets (id, name, asset_type, status, ip_address, hostname, os_family, os_version, criticality, business_unit, tags) VALUES
('c0000000-0000-0000-0000-000000000001', 'prod-web-01', 'linux_server', 'active', '10.0.1.10', 'prod-web-01.corp.local', 'Linux', 'Ubuntu 22.04 LTS', 5, 'Engineering', '["production","web","internet-facing"]'),
('c0000000-0000-0000-0000-000000000002', 'prod-db-01', 'linux_server', 'active', '10.0.1.20', 'prod-db-01.corp.local', 'Linux', 'RHEL 9.2', 5, 'Engineering', '["production","database","pci"]'),
('c0000000-0000-0000-0000-000000000003', 'win-dc-01', 'windows_server', 'active', '10.0.2.10', 'win-dc-01.corp.local', 'Windows', 'Windows Server 2022', 5, 'IT', '["production","domain-controller","critical"]'),
('c0000000-0000-0000-0000-000000000004', 'dev-app-01', 'linux_server', 'active', '10.0.3.10', 'dev-app-01.corp.local', 'Linux', 'Debian 12', 3, 'Engineering', '["development","application"]'),
('c0000000-0000-0000-0000-000000000005', 'corp-portal', 'web_application', 'active', '10.0.1.100', 'portal.corp.local', NULL, NULL, 4, 'Marketing', '["production","web-app","customer-facing"]'),
('c0000000-0000-0000-0000-000000000006', 'k8s-worker-01', 'docker_container', 'active', '10.0.4.10', 'k8s-worker-01.corp.local', 'Linux', 'Ubuntu 22.04 LTS', 4, 'Platform', '["production","kubernetes","container"]'),
('c0000000-0000-0000-0000-000000000007', 'aws-prod-vpc', 'cloud_asset', 'active', NULL, 'vpc-prod-us-east-1', NULL, NULL, 4, 'Cloud', '["aws","production","vpc"]'),
('c0000000-0000-0000-0000-000000000008', 'legacy-app-01', 'windows_server', 'active', '10.0.5.10', 'legacy-app-01.corp.local', 'Windows', 'Windows Server 2016', 2, 'Finance', '["legacy","eol-soon"]');

-- Sample software inventory
INSERT INTO asset_software (asset_id, name, version, vendor, cpe, package_manager) VALUES
('c0000000-0000-0000-0000-000000000001', 'nginx', '1.18.0', 'nginx inc', 'cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*', 'apt'),
('c0000000-0000-0000-0000-000000000001', 'openssl', '3.0.2', 'OpenSSL', 'cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*', 'apt'),
('c0000000-0000-0000-0000-000000000001', 'python3', '3.10.12', 'Python', 'cpe:2.3:a:python:python:3.10.12:*:*:*:*:*:*:*', 'apt'),
('c0000000-0000-0000-0000-000000000002', 'postgresql', '15.4', 'PostgreSQL', 'cpe:2.3:a:postgresql:postgresql:15.4:*:*:*:*:*:*:*', 'yum'),
('c0000000-0000-0000-0000-000000000002', 'openssl', '3.0.7', 'OpenSSL', 'cpe:2.3:a:openssl:openssl:3.0.7:*:*:*:*:*:*:*', 'yum'),
('c0000000-0000-0000-0000-000000000004', 'log4j', '2.14.1', 'Apache', 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*', 'maven'),
('c0000000-0000-0000-0000-000000000003', 'Microsoft Outlook', '16.0.17328', 'Microsoft', 'cpe:2.3:a:microsoft:outlook:16.0.17328:*:*:*:*:*:*:*', 'windows');

-- Sample open ports
INSERT INTO asset_ports (asset_id, port, protocol, service_name, service_version, state) VALUES
('c0000000-0000-0000-0000-000000000001', 22, 'tcp', 'ssh', 'OpenSSH 8.9', 'open'),
('c0000000-0000-0000-0000-000000000001', 80, 'tcp', 'http', 'nginx 1.18.0', 'open'),
('c0000000-0000-0000-0000-000000000001', 443, 'tcp', 'https', 'nginx 1.18.0', 'open'),
('c0000000-0000-0000-0000-000000000002', 5432, 'tcp', 'postgresql', '15.4', 'open'),
('c0000000-0000-0000-0000-000000000003', 389, 'tcp', 'ldap', NULL, 'open'),
('c0000000-0000-0000-0000-000000000003', 636, 'tcp', 'ldaps', NULL, 'open');

-- Sample vulnerabilities
INSERT INTO vulnerabilities (asset_id, cve_identifier, title, description, severity, cvss_score, epss_score, status, category, affected_software, affected_version, remediation, exploit_available, patch_available, risk_score) VALUES
('c0000000-0000-0000-0000-000000000001', 'CVE-2023-44487', 'HTTP/2 Rapid Reset Attack', 'nginx vulnerable to HTTP/2 Rapid Reset denial of service attack', 'high', 7.5, 0.94312, 'open', 'denial_of_service', 'nginx', '1.18.0', 'Upgrade nginx to version 1.25.3 or later', TRUE, TRUE, 85.5),
('c0000000-0000-0000-0000-000000000001', 'CVE-2024-1086', 'Linux Kernel Netfilter UAF', 'Use-after-free in netfilter subsystem allowing privilege escalation', 'high', 8.8, 0.042, 'assigned', 'privilege_escalation', 'linux_kernel', '5.15.0', 'Apply kernel patch or upgrade to patched version', TRUE, TRUE, 72.3),
('c0000000-0000-0000-0000-000000000004', 'CVE-2021-44228', 'Log4Shell RCE', 'Remote code execution via JNDI injection in Log4j', 'critical', 10.0, 0.97555, 'in_progress', 'remote_code_execution', 'log4j', '2.14.1', 'Upgrade to Log4j 2.17.1 or later immediately', TRUE, TRUE, 98.7),
('c0000000-0000-0000-0000-000000000003', 'CVE-2024-21413', 'Outlook RCE', 'Microsoft Outlook remote code execution via malicious link', 'critical', 9.8, 0.87654, 'open', 'remote_code_execution', 'Microsoft Outlook', '16.0.17328', 'Apply Microsoft security update KB5034763', TRUE, TRUE, 95.2),
('c0000000-0000-0000-0000-000000000002', NULL, 'PostgreSQL Weak Authentication', 'PostgreSQL configured with trust authentication for local connections', 'medium', 5.3, NULL, 'acknowledged', 'misconfiguration', 'postgresql', '15.4', 'Configure scram-sha-256 authentication', FALSE, FALSE, 45.0),
('c0000000-0000-0000-0000-000000000001', NULL, 'Missing Security Headers', 'Web server missing HSTS, CSP, and X-Frame-Options headers', 'medium', 4.3, NULL, 'open', 'misconfiguration', 'nginx', '1.18.0', 'Add security headers to nginx configuration', FALSE, FALSE, 38.5),
('c0000000-0000-0000-0000-000000000008', NULL, 'End-of-Life Operating System', 'Windows Server 2016 reached end of extended support', 'high', 7.0, NULL, 'risk_accepted', 'unsupported_software', 'Windows Server', '2016', 'Migrate to Windows Server 2022', FALSE, FALSE, 65.0);

-- Notification rules
INSERT INTO notification_rules (name, event_type, severity_threshold, channels, recipients, is_active) VALUES
('Critical Vulnerability Alert', 'vulnerability.detected', 'critical', '["email","slack"]', '["security-team@corp.local"]', TRUE),
('Failed Scan Alert', 'scan.failed', NULL, '["email"]', '["soc@corp.local"]', TRUE),
('New Asset Discovery', 'asset.discovered', NULL, '["slack"]', '["#security-alerts"]', TRUE);

-- Knowledge base entries (requires a user — skip created_by FK or use NULL)
INSERT INTO knowledge_base (title, category, content, tags, cve_ids) VALUES
('Log4Shell Remediation Guide', 'remediation', 'Step-by-step guide to identify and remediate Log4Shell (CVE-2021-44228) across Java applications. 1. Identify affected versions. 2. Upgrade to 2.17.1+. 3. Apply WAF rules as temporary mitigation.', '["log4j","rce","java"]', '["CVE-2021-44228"]'),
('HTTP/2 Rapid Reset Mitigation', 'remediation', 'Mitigate CVE-2023-44487 by upgrading web servers and applying rate limiting for HTTP/2 connections.', '["http2","dos","nginx"]', '["CVE-2023-44487"]');
