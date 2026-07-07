'use client';

import {
  MOCK_SCANS,
  MOCK_VULNERABILITIES,
  MOCK_WEB_FINDINGS,
  MOCK_CODE_REVIEWS,
  MOCK_RED_TEAM,
} from '@/lib/mock-data';
import { CodeReview, RedTeamCampaign, Scan, ScanStatus, ScanType, Vulnerability, WebScanFinding } from '@/types';

const KEYS = {
  scans: 'vulnshield_demo_scans',
  vulns: 'vulnshield_demo_vulns',
  webFindings: 'vulnshield_demo_web_findings',
  codeReviews: 'vulnshield_demo_code_reviews',
  redTeam: 'vulnshield_demo_redteam',
} as const;

function read<T>(key: string, fallback: T[]): T[] {
  if (typeof window === 'undefined') return fallback;
  try {
    const raw = sessionStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T[]) : fallback;
  } catch {
    return fallback;
  }
}

function write<T>(key: string, data: T[]) {
  if (typeof window === 'undefined') return;
  sessionStorage.setItem(key, JSON.stringify(data));
}

function uid() {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
}

export const demoStore = {
  getScans(): Scan[] {
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
    const scans = [scan, ...this.getScans()];
    write(KEYS.scans, scans);
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
    const started = this.updateScan(id, {
      status: 'running',
      started_at: new Date().toISOString(),
    });
    if (!started) return null;

    setTimeout(() => {
      this.updateScan(id, {
        status: 'completed',
        completed_at: new Date().toISOString(),
        duration_seconds: 120,
        findings_count: 8 + Math.floor(Math.random() * 12),
        critical_count: Math.floor(Math.random() * 2),
        high_count: 2 + Math.floor(Math.random() * 4),
        medium_count: 3 + Math.floor(Math.random() * 5),
        low_count: 2 + Math.floor(Math.random() * 4),
        info_count: 1,
      });
    }, 2500);

    return started;
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
    const finding: WebScanFinding = {
      id: uid(),
      scan_id: uid(),
      url,
      vulnerability_type: 'Security Headers',
      owasp_category: 'A05:2021',
      severity: 'medium',
      title: `Missing security headers on ${host}`,
      description: 'Detected missing HSTS and Content-Security-Policy headers during active scan.',
      created_at: new Date().toISOString(),
    };
    const items = [finding, ...this.getWebFindings()];
    write(KEYS.webFindings, items);
    return items;
  },

  getCodeReviews(): CodeReview[] {
    return read(KEYS.codeReviews, MOCK_CODE_REVIEWS);
  },

  createCodeReview(repo: string, language: string): CodeReview {
    const review: CodeReview = {
      id: uid(),
      repository_url: repo,
      branch: 'main',
      language,
      status: 'running' as ScanStatus,
      findings_count: 0,
      started_at: new Date().toISOString(),
      created_at: new Date().toISOString(),
    };
    const items = [review, ...this.getCodeReviews()];
    write(KEYS.codeReviews, items);

    setTimeout(() => {
      const list = this.getCodeReviews();
      const i = list.findIndex((r) => r.id === review.id);
      if (i >= 0) {
        list[i] = {
          ...list[i],
          status: 'completed',
          findings_count: 3 + Math.floor(Math.random() * 5),
          completed_at: new Date().toISOString(),
        };
        write(KEYS.codeReviews, list);
      }
    }, 3000);

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
    const items = [campaign, ...this.getRedTeamCampaigns()];
    write(KEYS.redTeam, items);

    setTimeout(() => {
      const list = this.getRedTeamCampaigns();
      const i = list.findIndex((c) => c.id === campaign.id);
      if (i >= 0) {
        list[i] = {
          ...list[i],
          status: 'completed',
          findings_count: 5 + Math.floor(Math.random() * 8),
          completed_at: new Date().toISOString(),
          executive_summary: 'Campaign identified lateral movement and credential exposure paths.',
        };
        write(KEYS.redTeam, list);
      }
    }, 4000);

    return campaign;
  },
};
