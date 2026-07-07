'use client';

import {
  MOCK_SCANS,
  MOCK_VULNERABILITIES,
  MOCK_WEB_FINDINGS,
  MOCK_CODE_REVIEWS,
  MOCK_RED_TEAM,
  MOCK_REPORTS,
} from '@/lib/mock-data';
import { ExecutiveReportInput } from '@/lib/executive-pdf-types';
import { CodeReview, RedTeamCampaign, Report, Scan, ScanStatus, ScanType, Vulnerability, WebScanFinding } from '@/types';

const KEYS = {
  scans: 'vulnshield_demo_scans',
  vulns: 'vulnshield_demo_vulns',
  webFindings: 'vulnshield_demo_web_findings',
  codeReviews: 'vulnshield_demo_code_reviews',
  redTeam: 'vulnshield_demo_redteam',
  reportInputs: 'vulnshield_demo_report_inputs',
  reportKeys: 'vulnshield_demo_report_keys',
  reports: 'vulnshield_demo_reports',
  seeded: 'vulnshield_demo_seeded',
} as const;

export interface CodeReviewFinding {
  id: string;
  review_id: string;
  title: string;
  severity: string;
  category?: string;
  description?: string;
  recommended_fix?: string;
  owasp_category?: string;
  cwe_id?: string;
  file_path?: string;
  line_start?: number;
  line_end?: number;
}

export interface RedTeamFinding {
  id: string;
  campaign_id: string;
  title: string;
  severity: string;
  description?: string;
  remediation?: string;
  mitre_technique_id?: string;
  mitre_tactic?: string;
  proof?: string;
}

function read<T>(key: string, fallback: T[]): T[] {
  if (typeof window === 'undefined') return fallback;
  try {
    const raw = sessionStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T[]) : fallback;
  } catch {
    return fallback;
  }
}

function readMap(key: string): Record<string, ExecutiveReportInput> {
  if (typeof window === 'undefined') return {};
  try {
    const raw = sessionStorage.getItem(key);
    return raw ? (JSON.parse(raw) as Record<string, ExecutiveReportInput>) : {};
  } catch {
    return {};
  }
}

function write<T>(key: string, data: T[]) {
  if (typeof window === 'undefined') return;
  sessionStorage.setItem(key, JSON.stringify(data));
}

function writeMap(key: string, data: Record<string, ExecutiveReportInput>) {
  if (typeof window === 'undefined') return;
  sessionStorage.setItem(key, JSON.stringify(data));
}

function readReportKeys(): Record<string, string> {
  if (typeof window === 'undefined') return {};
  try {
    const raw = sessionStorage.getItem(KEYS.reportKeys);
    return raw ? (JSON.parse(raw) as Record<string, string>) : {};
  } catch {
    return {};
  }
}

function writeReportKeys(data: Record<string, string>) {
  if (typeof window === 'undefined') return;
  sessionStorage.setItem(KEYS.reportKeys, JSON.stringify(data));
}

function buildScanReportInput(scan: Scan): ExecutiveReportInput {
  const vulns = read(KEYS.vulns, MOCK_VULNERABILITIES).slice(0, 15);
  const findings = vulns.map((v) => ({
    title: v.title,
    severity: v.severity,
    category: 'Vulnerability',
    description: v.description,
    remediation: v.remediation || 'Apply vendor patch and verify remediation.',
    cwe_id: v.cve_identifier,
    cvss_score: v.cvss_score,
  }));
  return {
    reportTitle: `Vulnerability Scan — ${scan.name}`,
    assessmentType: 'Vulnerability Assessment',
    target: scan.name,
    executiveSummary: `Scan identified ${scan.findings_count ?? findings.length} findings (${scan.critical_count ?? 0} critical, ${scan.high_count ?? 0} high). Immediate remediation recommended for critical items.`,
    methodology: 'CVE correlation, CVSS prioritization, configuration assessment, and risk-based triage aligned with industry standards.',
    findings,
    severityCounts: {
      critical: scan.critical_count ?? 0,
      high: scan.high_count ?? 0,
      medium: scan.medium_count ?? 0,
      low: scan.low_count ?? 0,
      info: scan.info_count ?? 0,
    },
  };
}

function uid() {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
}

function analyzeCodeDemo(code: string, filePath: string): CodeReviewFinding[] {
  const findings: CodeReviewFinding[] = [];
  const lines = code.split('\n');
  const rules = [
    { re: /eval\s*\(/i, title: 'Use of eval()', severity: 'critical', cwe: 'CWE-95', owasp: 'A03:2021' },
    { re: /password\s*=\s*['"][^'"]+['"]/i, title: 'Hardcoded credential', severity: 'critical', cwe: 'CWE-798', owasp: 'A07:2021' },
    { re: /innerHTML\s*=/i, title: 'DOM XSS sink', severity: 'high', cwe: 'CWE-79', owasp: 'A03:2021' },
    { re: /pickle\.loads/i, title: 'Unsafe deserialization', severity: 'critical', cwe: 'CWE-502', owasp: 'A08:2021' },
    { re: /shell\s*=\s*True/i, title: 'Command injection risk', severity: 'high', cwe: 'CWE-78', owasp: 'A03:2021' },
  ];
  lines.forEach((line, i) => {
    rules.forEach((rule) => {
      if (rule.re.test(line)) {
        findings.push({
          id: uid(),
          review_id: '',
          title: rule.title,
          severity: rule.severity,
          category: 'SAST',
          description: `Security anti-pattern detected on line ${i + 1}.`,
          recommended_fix: 'Refactor to eliminate unsafe pattern. Follow OWASP secure coding guidelines.',
          owasp_category: rule.owasp,
          cwe_id: rule.cwe,
          file_path: filePath,
          line_start: i + 1,
          line_end: i + 1,
        });
      }
    });
  });
  return findings;
}

const DEMO_REDTEAM_FINDINGS: Omit<RedTeamFinding, 'id' | 'campaign_id'>[] = [
  {
    title: 'Credential exposure via weak service account',
    severity: 'critical',
    description: 'Service account with excessive privileges in campaign scope.',
    remediation: 'Enforce least privilege, rotate credentials, enable MFA.',
    mitre_technique_id: 'T1078',
    mitre_tactic: 'Credential Access',
    proof: 'Simulated credential harvest from misconfigured vault.',
  },
  {
    title: 'Lateral movement via flat network',
    severity: 'high',
    description: 'Unsegmented network allows pivot from DMZ to internal tier.',
    remediation: 'Implement micro-segmentation and zero-trust access.',
    mitre_technique_id: 'T1021',
    mitre_tactic: 'Lateral Movement',
    proof: 'Simulated SSH hop between network zones.',
  },
  {
    title: 'Missing EDR on endpoints',
    severity: 'high',
    description: 'Endpoints without EDR agents detected.',
    remediation: 'Deploy EDR universally with tamper protection.',
    mitre_technique_id: 'T1562',
    mitre_tactic: 'Defense Evasion',
    proof: 'Payload execution without alert on sampled hosts.',
  },
];

function ensureSeedData() {
  if (typeof window === 'undefined') return;
  if (sessionStorage.getItem(KEYS.seeded)) return;

  const map = readMap(KEYS.reportInputs);
  const keys = readReportKeys();
  let reports = read(KEYS.reports, MOCK_REPORTS);

  MOCK_SCANS.filter((s) => s.status === 'completed').forEach((scan) => {
    const entityKey = `scan:${scan.id}`;
    if (!map[entityKey]) map[entityKey] = buildScanReportInput(scan);
  });

  const seedReview = MOCK_CODE_REVIEWS.find((r) => r.status === 'completed');
  if (seedReview && !map[`codereview:${seedReview.id}`]) {
    const reviewKey = `codereview:${seedReview.id}`;
    map[reviewKey] = {
      reportTitle: `SAST Report — ${seedReview.repository_url}`,
      assessmentType: 'Application Security Code Review',
      target: seedReview.repository_url || 'repository',
      executiveSummary: `Static analysis identified ${seedReview.findings_count} security issues requiring remediation before production release.`,
      methodology: 'Pattern-based SAST (OWASP, CWE), secrets detection, injection analysis, and insecure API usage checks.',
      findings: [
        { title: 'Hardcoded credential', severity: 'critical', category: 'SAST', cwe_id: 'CWE-798', remediation: 'Use secrets manager.' },
        { title: 'SQL injection risk', severity: 'high', category: 'SAST', cwe_id: 'CWE-89', remediation: 'Use parameterized queries.' },
      ],
      severityCounts: { critical: 1, high: 1 },
    };
    keys[`seed-review-${seedReview.id}`] = reviewKey;
    if (!reports.some((r) => r.source_entity_key === reviewKey)) {
      reports = [{
        id: `seed-review-${seedReview.id}`,
        name: `Executive Code Review — ${seedReview.language}`,
        report_type: 'technical',
        format: 'pdf',
        status: 'completed',
        generated_at: seedReview.completed_at,
        created_at: seedReview.created_at,
        source_entity_key: reviewKey,
      }, ...reports];
    }
  }

  const seedCampaign = MOCK_RED_TEAM.find((c) => c.status === 'completed');
  if (seedCampaign && !map[`redteam:${seedCampaign.id}`]) {
    const campaignKey = `redteam:${seedCampaign.id}`;
    map[campaignKey] = {
      reportTitle: `Red Team Assessment — ${seedCampaign.name}`,
      assessmentType: 'Adversary Simulation (MITRE ATT&CK)',
      target: seedCampaign.name,
      executiveSummary: `Campaign identified ${seedCampaign.findings_count} attack paths including credential exposure and lateral movement.`,
      methodology: 'MITRE ATT&CK-mapped attack simulation covering initial access through impact phases.',
      findings: DEMO_REDTEAM_FINDINGS.map((f) => ({
        title: f.title,
        severity: f.severity,
        description: f.description,
        remediation: f.remediation,
        proof: f.proof,
        category: f.mitre_tactic,
      })),
      severityCounts: { critical: 1, high: 2 },
    };
    keys[`seed-campaign-${seedCampaign.id}`] = campaignKey;
    if (!reports.some((r) => r.source_entity_key === campaignKey)) {
      reports = [{
        id: `seed-campaign-${seedCampaign.id}`,
        name: `Executive Red Team — ${seedCampaign.name}`,
        report_type: 'executive',
        format: 'pdf',
        status: 'completed',
        generated_at: seedCampaign.completed_at,
        created_at: seedCampaign.created_at,
        source_entity_key: campaignKey,
      }, ...reports];
    }
  }

  reports = reports.map((r) => {
    if (r.source_entity_key) return r;
    if (r.id === '1') return { ...r, source_entity_key: 'scan:1' };
    return r;
  });

  keys['1'] = keys['1'] || 'scan:1';

  if (seedReview) {
    const reviewReportId = 'review-seed-1';
    if (!reports.some((r) => r.source_entity_key === `codereview:${seedReview.id}`)) {
      reports.unshift({
        id: reviewReportId,
        name: `Executive Code Review — ${seedReview.language}`,
        report_type: 'technical',
        format: 'pdf',
        status: 'completed',
        generated_at: seedReview.completed_at,
        created_at: seedReview.created_at,
        source_entity_key: `codereview:${seedReview.id}`,
      });
      keys[reviewReportId] = `codereview:${seedReview.id}`;
    }
  }

  if (seedCampaign) {
    const campaignReportId = 'campaign-seed-1';
    if (!reports.some((r) => r.source_entity_key === `redteam:${seedCampaign.id}`)) {
      reports.unshift({
        id: campaignReportId,
        name: `Executive Red Team — ${seedCampaign.name}`,
        report_type: 'executive',
        format: 'pdf',
        status: 'completed',
        generated_at: seedCampaign.completed_at,
        created_at: seedCampaign.created_at,
        source_entity_key: `redteam:${seedCampaign.id}`,
      });
      keys[campaignReportId] = `redteam:${seedCampaign.id}`;
    }
  }

  writeMap(KEYS.reportInputs, map);
  writeReportKeys(keys);
  write(KEYS.reports, reports);
  sessionStorage.setItem(KEYS.seeded, '1');
}

export const demoStore = {
  getScans(): Scan[] {
    ensureSeedData();
    return read(KEYS.scans, MOCK_SCANS);
  },

  createScan(input: { name: string; scan_type: ScanType; target_asset_id?: string }): Scan {
    const scan: Scan = {
      id: uid(),
      name: input.name,
      scan_type: input.scan_type,
      status: 'queued',
      target_asset_id: input.target_asset_id,
      findings_count: 0,
      critical_count: 0,
      high_count: 0,
      medium_count: 0,
      low_count: 0,
      info_count: 0,
      created_at: new Date().toISOString(),
    };
    write(KEYS.scans, [scan, ...this.getScans()]);
    return scan;
  },

  updateScan(id: string, patch: Partial<Scan>): Scan | null {
    const scans = this.getScans();
    const idx = scans.findIndex((s) => s.id === id);
    if (idx < 0) return null;
    scans[idx] = { ...scans[idx], ...patch };
    write(KEYS.scans, scans);
    return scans[idx];
  },

  startScan(id: string): Scan | null {
    const started = this.updateScan(id, { status: 'running', started_at: new Date().toISOString() });
    if (!started) return null;

    setTimeout(() => {
      const crit = 1 + Math.floor(Math.random() * 2);
      const high = 2 + Math.floor(Math.random() * 3);
      const med = 3 + Math.floor(Math.random() * 4);
      const low = 2 + Math.floor(Math.random() * 3);
      const info = 1;
      const total = crit + high + med + low + info;
      const scan = this.updateScan(id, {
        status: 'completed',
        completed_at: new Date().toISOString(),
        duration_seconds: 120,
        findings_count: total,
        critical_count: crit,
        high_count: high,
        medium_count: med,
        low_count: low,
        info_count: info,
      });
      if (scan) this._saveScanReport(scan);
    }, 1500);

    return started;
  },

  _saveScanReport(scan: Scan) {
    const entityKey = `scan:${scan.id}`;
    const input = buildScanReportInput(scan);
    const map = readMap(KEYS.reportInputs);
    map[entityKey] = input;
    writeMap(KEYS.reportInputs, map);
    this._addReport(`Executive Scan — ${scan.name}`, 'executive', entityKey);
  },

  getVulnerabilities(): Vulnerability[] {
    return read(KEYS.vulns, MOCK_VULNERABILITIES);
  },

  updateVulnerabilityStatus(id: string, status: Vulnerability['status']): Vulnerability | null {
    const vulns = this.getVulnerabilities();
    const idx = vulns.findIndex((v) => v.id === id);
    if (idx < 0) return null;
    vulns[idx] = { ...vulns[idx], status };
    write(KEYS.vulns, vulns);
    return vulns[idx];
  },

  getWebFindings(): WebScanFinding[] {
    return read(KEYS.webFindings, MOCK_WEB_FINDINGS);
  },

  startWebScan(url: string): WebScanFinding[] {
    let host = url;
    try {
      host = new URL(url.startsWith('http') ? url : `https://${url}`).hostname;
    } catch {
      host = url.replace(/^https?:\/\//, '').split('/')[0] || 'target';
    }
    const findings: WebScanFinding[] = [
      {
        id: uid(),
        scan_id: uid(),
        url,
        vulnerability_type: 'Security Headers',
        owasp_category: 'A05:2021',
        severity: 'medium',
        title: `Missing security headers on ${host}`,
        description: 'Missing HSTS and Content-Security-Policy headers.',
        remediation: 'Add Strict-Transport-Security, CSP, X-Frame-Options, and X-Content-Type-Options headers.',
        created_at: new Date().toISOString(),
      },
      {
        id: uid(),
        scan_id: uid(),
        url,
        vulnerability_type: 'SQL Injection',
        owasp_category: 'A03:2021',
        severity: 'high',
        title: `Potential SQL injection in search parameter`,
        description: 'Unsanitized input reflected in database query.',
        remediation: 'Use parameterized queries and input validation.',
        created_at: new Date().toISOString(),
      },
    ];
    write(KEYS.webFindings, [...findings, ...this.getWebFindings()]);
    const map = readMap(KEYS.reportInputs);
    map[`webscan:${url}`] = {
      reportTitle: `DAST Report — ${host}`,
      assessmentType: 'Web Application Security Test',
      target: url,
      executiveSummary: `Active DAST identified ${findings.length} issues including missing security headers and injection risks.`,
      methodology: 'OWASP Top 10 testing, crawl-based discovery, active payload injection, and security header analysis.',
      findings: findings.map((f) => ({
        title: f.title,
        severity: f.severity,
        category: f.vulnerability_type,
        owasp_category: f.owasp_category,
        description: f.description,
        remediation: f.remediation,
        location: f.url,
      })),
      severityCounts: { high: 1, medium: 1 },
    };
    writeMap(KEYS.reportInputs, map);
    return findings;
  },

  getCodeReviews(): CodeReview[] {
    return read(KEYS.codeReviews, MOCK_CODE_REVIEWS);
  },

  createCodeReview(input: {
    repository_url?: string;
    language: string;
    source_code?: string;
    file_path?: string;
    branch?: string;
  }): CodeReview {
    const target = input.repository_url || input.file_path || 'pasted-code';
    const review: CodeReview = {
      id: uid(),
      repository_url: input.repository_url || input.file_path,
      branch: input.branch || 'main',
      language: input.language,
      status: 'running' as ScanStatus,
      findings_count: 0,
      started_at: new Date().toISOString(),
      created_at: new Date().toISOString(),
    };
    write(KEYS.codeReviews, [review, ...this.getCodeReviews()]);

    setTimeout(() => {
      const code = input.source_code || 'password = "admin123"\neval(user_input)';
      const filePath = input.file_path || `main.${input.language.slice(0, 2)}`;
      const findings = analyzeCodeDemo(code, filePath);
      findings.forEach((f) => { f.review_id = review.id; });

      const list = this.getCodeReviews();
      const i = list.findIndex((r) => r.id === review.id);
      if (i >= 0) {
        list[i] = {
          ...list[i],
          status: 'completed',
          findings_count: findings.length,
          completed_at: new Date().toISOString(),
        };
        write(KEYS.codeReviews, list);
      }

      const map = readMap(KEYS.reportInputs);
      map[`codereview:${review.id}`] = {
        reportTitle: `SAST Report — ${target}`,
        assessmentType: 'Application Security Code Review',
        target,
        executiveSummary: `Static analysis identified ${findings.length} security issues requiring remediation before production release.`,
        methodology: 'Pattern-based SAST (OWASP, CWE), secrets detection, injection analysis, and insecure API usage checks.',
        findings: findings.map((f) => ({
          title: f.title,
          severity: f.severity,
          category: f.category,
          description: f.description,
          remediation: f.recommended_fix,
          owasp_category: f.owasp_category,
          cwe_id: f.cwe_id,
          file_path: f.file_path,
          line_start: f.line_start,
          line_end: f.line_end,
        })),
        severityCounts: findings.reduce((acc, f) => {
          acc[f.severity] = (acc[f.severity] || 0) + 1;
          return acc;
        }, {} as Record<string, number>),
      };
      writeMap(KEYS.reportInputs, map);
      this._addReport(`Executive Code Review — ${input.language}`, 'technical', `codereview:${review.id}`);
    }, 2000);

    return review;
  },

  getRedTeamCampaigns(): RedTeamCampaign[] {
    return read(KEYS.redTeam, MOCK_RED_TEAM);
  },

  createRedTeamCampaign(name: string, description: string): RedTeamCampaign {
    const campaign: RedTeamCampaign = {
      id: uid(),
      name,
      description,
      status: 'running',
      findings_count: 0,
      started_at: new Date().toISOString(),
      created_at: new Date().toISOString(),
    };
    write(KEYS.redTeam, [campaign, ...this.getRedTeamCampaigns()]);

    setTimeout(() => {
      const findings = DEMO_REDTEAM_FINDINGS.map((f) => ({ ...f, id: uid(), campaign_id: campaign.id }));
      const list = this.getRedTeamCampaigns();
      const i = list.findIndex((c) => c.id === campaign.id);
      if (i >= 0) {
        list[i] = {
          ...list[i],
          status: 'completed',
          findings_count: findings.length,
          completed_at: new Date().toISOString(),
          executive_summary: `Campaign identified ${findings.length} attack paths including credential exposure and lateral movement.`,
        };
        write(KEYS.redTeam, list);
      }

      const map = readMap(KEYS.reportInputs);
      map[`redteam:${campaign.id}`] = {
        reportTitle: `Red Team Assessment — ${name}`,
        assessmentType: 'Adversary Simulation (MITRE ATT&CK)',
        target: name,
        executiveSummary: list[i]?.executive_summary || '',
        methodology: 'MITRE ATT&CK-mapped attack simulation covering initial access through impact phases.',
        findings: findings.map((f) => ({
          title: f.title,
          severity: f.severity,
          description: f.description,
          remediation: f.remediation,
          proof: f.proof,
          location: f.mitre_technique_id,
          category: f.mitre_tactic,
        })),
        severityCounts: { critical: 1, high: 2 },
      };
      writeMap(KEYS.reportInputs, map);
      this._addReport(`Executive Red Team — ${name}`, 'executive', `redteam:${campaign.id}`);
    }, 2500);

    return campaign;
  },

  getReportInput(key: string): ExecutiveReportInput | undefined {
    ensureSeedData();
    return readMap(KEYS.reportInputs)[key];
  },

  getReportEntityKey(reportId: string): string | undefined {
    ensureSeedData();
    const keys = readReportKeys();
    if (keys[reportId]) return keys[reportId];
    const report = read(KEYS.reports, MOCK_REPORTS).find((r) => r.id === reportId);
    return report?.source_entity_key;
  },

  getReports(): Report[] {
    ensureSeedData();
    return read(KEYS.reports, MOCK_REPORTS);
  },

  _addReport(name: string, reportType: Report['report_type'], entityKey: string) {
    const report: Report = {
      id: uid(),
      name,
      report_type: reportType,
      format: 'pdf',
      status: 'completed',
      generated_at: new Date().toISOString(),
      created_at: new Date().toISOString(),
      source_entity_key: entityKey,
    };
    const keys = readReportKeys();
    keys[report.id] = entityKey;
    writeReportKeys(keys);
    write(KEYS.reports, [report, ...read(KEYS.reports, MOCK_REPORTS)]);
    return report;
  },
};
