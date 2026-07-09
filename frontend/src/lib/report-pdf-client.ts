'use client';

import {
  codeReviewApi,
  redTeamApi,
  scansApi,
  vulnerabilitiesApi,
  webScannerApi,
} from '@/lib/api';
import type { ExecutiveFinding, ExecutiveReportInput } from '@/lib/executive-pdf-types';
import type { WebScanFinding } from '@/types';

const METHODOLOGY = {
  scan:
    'Vulnerability assessment combining authenticated/unauthenticated scanning, CVE correlation, and risk-based prioritization (CVSS v3.1, CIS Controls).',
  codereview:
    'Static Application Security Testing (SAST) using Semgrep rulesets (OWASP Top 10, CWE) and LLM-assisted triage.',
  redteam:
    'Adversary simulation mapped to MITRE ATT&CK with proof-of-concept narratives and prioritized remediation.',
  webscan:
    'Dynamic Application Security Testing (DAST) including crawl, OWASP Top 10 test cases, and security header analysis.',
};

function severityCounts(findings: ExecutiveFinding[]): Record<string, number> {
  return findings.reduce<Record<string, number>>((acc, f) => {
    const sev = String(f.severity || 'medium').toLowerCase();
    acc[sev] = (acc[sev] || 0) + 1;
    return acc;
  }, {});
}

function mapFinding(raw: Record<string, unknown>): ExecutiveFinding {
  return {
    title: String(raw.title ?? 'Finding'),
    severity: String(raw.severity ?? 'medium'),
    category: raw.category as string | undefined,
    description: raw.description as string | undefined,
    remediation: (raw.remediation ?? raw.recommended_fix) as string | undefined,
    recommended_fix: raw.recommended_fix as string | undefined,
    owasp_category: raw.owasp_category as string | undefined,
    cwe_id: raw.cwe_id as string | undefined,
    cvss_score: raw.cvss_score as number | undefined,
    file_path: raw.file_path as string | undefined,
    line_start: raw.line_start as number | undefined,
    line_end: raw.line_end as number | undefined,
    location: raw.location as string | undefined,
    proof: raw.proof as string | undefined,
    root_cause: raw.root_cause as string | undefined,
  };
}

async function buildCodereviewInput(reviewId: string): Promise<ExecutiveReportInput> {
  const review = await codeReviewApi.get(reviewId);
  const rawFindings = await codeReviewApi.getFindings(reviewId);
  const findings = (rawFindings as Record<string, unknown>[]).map(mapFinding);
  const target = review.repository_url || `${review.language} source`;
  return {
    reportTitle: `SAST Report — ${target.slice(0, 60)}`,
    assessmentType: 'Application Security Code Review',
    target,
    executiveSummary: `Static application security review of ${target} (${review.language}) identified ${review.findings_count ?? findings.length} issues.`,
    methodology: METHODOLOGY.codereview,
    findings,
    severityCounts: severityCounts(findings),
    metadata: { 'Review ID': reviewId, Language: review.language || '—' },
  };
}

async function buildScanInput(scanId: string): Promise<ExecutiveReportInput> {
  const scan = await scansApi.get(scanId);
  const vulns = await vulnerabilitiesApi.list({ scan_id: scanId, page_size: 100 });
  const findings: ExecutiveFinding[] = vulns.items.map((v) => ({
    title: v.title,
    severity: v.severity,
    category: 'Vulnerability',
    description: v.description,
    remediation: v.remediation,
    cvss_score: v.cvss_score,
    location: v.cve_identifier,
  }));
  const counts = {
    critical: scan.critical_count ?? 0,
    high: scan.high_count ?? 0,
    medium: scan.medium_count ?? 0,
    low: scan.low_count ?? 0,
    info: scan.info_count ?? 0,
  };
  return {
    reportTitle: `Vulnerability Scan — ${scan.name}`,
    assessmentType: 'Vulnerability Assessment',
    target: scan.name,
    executiveSummary: `Assessment '${scan.name}' identified ${scan.findings_count ?? findings.length} findings.`,
    methodology: METHODOLOGY.scan,
    findings,
    severityCounts: counts,
    metadata: { 'Scan ID': scanId, 'Scan Type': scan.scan_type },
  };
}

async function buildRedteamInput(campaignId: string): Promise<ExecutiveReportInput> {
  const campaign = await redTeamApi.get(campaignId);
  const rawFindings = await redTeamApi.getFindings(campaignId);
  const findings = (rawFindings as Record<string, unknown>[]).map(mapFinding);
  return {
    reportTitle: `Red Team Assessment — ${campaign.name}`,
    assessmentType: 'Adversary Simulation (MITRE ATT&CK)',
    target: campaign.name,
    executiveSummary:
      campaign.executive_summary ||
      `Red team campaign '${campaign.name}' completed with ${campaign.findings_count ?? findings.length} findings.`,
    methodology: METHODOLOGY.redteam,
    findings,
    severityCounts: severityCounts(findings),
    metadata: { 'Campaign ID': campaignId },
  };
}

async function buildWebscanInput(scanId: string): Promise<ExecutiveReportInput> {
  const scan = await webScannerApi.get(scanId);
  const rawFindings = await webScannerApi.getFindings(scanId);
  const findings: ExecutiveFinding[] = (rawFindings as WebScanFinding[]).map((f) => ({
    title: f.title,
    severity: f.severity,
    category: f.vulnerability_type,
    description: f.description,
    remediation: f.remediation,
    owasp_category: f.owasp_category,
    location: f.url,
  }));
  return {
    reportTitle: `DAST Report — ${scan.target_url}`,
    assessmentType: 'Web Application Security Test',
    target: scan.target_url,
    executiveSummary: `Dynamic scan of ${scan.target_url} identified ${scan.findings_count ?? findings.length} issues.`,
    methodology: METHODOLOGY.webscan,
    findings,
    severityCounts: severityCounts(findings),
    metadata: { 'Scan ID': scanId },
  };
}

export async function buildReportInputFromEntity(
  entityType: 'scan' | 'codereview' | 'redteam' | 'webscan',
  entityId: string
): Promise<ExecutiveReportInput> {
  switch (entityType) {
    case 'codereview':
      return buildCodereviewInput(entityId);
    case 'scan':
      return buildScanInput(entityId);
    case 'redteam':
      return buildRedteamInput(entityId);
    case 'webscan':
      return buildWebscanInput(entityId);
    default:
      throw new Error('Unsupported report type');
  }
}
