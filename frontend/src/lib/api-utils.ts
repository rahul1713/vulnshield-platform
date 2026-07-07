import {
  ComplianceScorePoint,
  DashboardData,
  HeatmapCell,
  PaginatedResponse,
  RemediationProgress,
  RiskTrendPoint,
  SearchResult,
  SeverityDistribution,
} from '@/types';
import { MOCK_DASHBOARD } from '@/lib/mock-data';

export function normalizePaginated<T>(
  data: unknown,
  page = 1,
  pageSize = 10
): PaginatedResponse<T> {
  if (Array.isArray(data)) {
    const items = data as T[];
    return {
      items,
      total: items.length,
      page,
      page_size: pageSize,
      total_pages: Math.max(1, Math.ceil(items.length / pageSize)),
    };
  }
  if (data && typeof data === 'object' && 'items' in data) {
    const p = data as PaginatedResponse<T>;
    return {
      items: p.items ?? [],
      total: p.total ?? p.items?.length ?? 0,
      page: p.page ?? page,
      page_size: p.page_size ?? pageSize,
      total_pages: p.total_pages ?? 1,
    };
  }
  return { items: [], total: 0, page, page_size: pageSize, total_pages: 0 };
}

export function normalizeDashboard(data: unknown): DashboardData {
  if (!data || typeof data !== 'object') return MOCK_DASHBOARD;
  const d = data as Record<string, unknown>;

  if ('stats' in d && d.stats) {
    return d as unknown as DashboardData;
  }

  const severity = (d.severity_distribution as SeverityDistribution[]) ?? MOCK_DASHBOARD.severity_distribution;

  const riskTrendRaw = (d.risk_trend ?? d.risk_trends) as Array<Record<string, unknown>> | undefined;
  const risk_trends: RiskTrendPoint[] = riskTrendRaw?.length
    ? riskTrendRaw.map((p) => ({
        date: String(p.date ?? ''),
        critical: Number(p.critical ?? p.count ?? 0),
        high: Number(p.high ?? 0),
        medium: Number(p.medium ?? 0),
        overall_risk: Number(p.overall_risk ?? p.count ?? 0),
      }))
    : MOCK_DASHBOARD.risk_trends;

  let remediation_progress: RemediationProgress[] = MOCK_DASHBOARD.remediation_progress;
  const rem = d.remediation_progress;
  if (Array.isArray(rem)) {
    remediation_progress = rem as RemediationProgress[];
  } else if (rem && typeof rem === 'object') {
    remediation_progress = Object.entries(rem as Record<string, number>).map(([status, count]) => ({
      month: status.replace(/_/g, ' '),
      opened: count,
      resolved: status.includes('resolved') || status.includes('closed') ? count : 0,
    }));
  }

  const topAssets = (d.top_vulnerable_assets as Array<Record<string, unknown>>) ?? [];
  const risk_heatmap: HeatmapCell[] = topAssets.length
    ? topAssets.flatMap((a) => [
        { asset: String(a.name ?? a.hostname ?? 'Asset'), category: 'Vulnerabilities', value: Number(a.vulnerability_count ?? a.vuln_count ?? 0) * 5 },
        { asset: String(a.name ?? a.hostname ?? 'Asset'), category: 'Risk', value: Number(a.max_risk ?? 0) },
      ])
    : MOCK_DASHBOARD.risk_heatmap;

  const compliance_scores: ComplianceScorePoint[] =
    (d.compliance_scores as ComplianceScorePoint[]) ??
    [{ framework: 'Overall', score: Number(d.compliance_score ?? 75) }];

  return {
    stats: {
      total_assets: Number(d.total_assets ?? 0),
      total_vulnerabilities: Number(d.total_vulnerabilities ?? 0),
      critical_vulnerabilities: Number(d.critical_count ?? d.critical_vulnerabilities ?? 0),
      high_vulnerabilities: Number(d.high_count ?? d.high_vulnerabilities ?? 0),
      open_vulnerabilities: Number(d.open_count ?? d.open_vulnerabilities ?? 0),
      resolved_this_month: Number(d.resolved_count ?? d.resolved_this_month ?? 0),
      active_scans: Number(d.active_scans ?? 0),
      compliance_score: Number(d.compliance_score ?? 0),
      mean_time_to_remediate_days: Number(d.mean_time_to_remediate_days ?? 14),
      risk_score: Number(d.risk_score ?? 0),
    },
    severity_distribution: severity,
    risk_trends,
    remediation_progress,
    risk_heatmap,
    compliance_scores,
  };
}

export function normalizeSearchResults(data: unknown): SearchResult[] {
  if (!Array.isArray(data)) return [];
  return data.map((item) => {
    const r = item as Record<string, unknown>;
    return {
      type: r.type as SearchResult['type'],
      id: String(r.id ?? ''),
      title: String(r.title ?? ''),
      subtitle: r.subtitle ? String(r.subtitle) : undefined,
      href: String(r.href ?? r.url ?? '/dashboard'),
    };
  });
}

export function listParamsToOffset(params?: { page?: number; page_size?: number }) {
  const page = params?.page ?? 1;
  const pageSize = params?.page_size ?? 50;
  return { limit: pageSize, offset: (page - 1) * pageSize, page, pageSize };
}
