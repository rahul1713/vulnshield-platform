'use client';

import { Box } from '@mui/material';
import {
  BugReport,
  CheckCircle,
  Radar,
  Storage,
  TrendingUp,
  Warning,
} from '@mui/icons-material';
import { useQuery } from '@tanstack/react-query';
import { dashboardApi } from '@/lib/api';
import { MOCK_DASHBOARD } from '@/lib/mock-data';
import { StatCard, StatCardsGrid } from '@/components/ui/StatCards';
import {
  SeverityDistributionChart,
  RiskTrendChart,
  RemediationProgressChart,
  RiskHeatmapChart,
  ComplianceScoreChart,
} from '@/components/charts/DashboardCharts';
import { PageHeader } from '@/components/ui/PageHeader';
import { DashboardData } from '@/types';

interface DashboardViewProps {
  title: string;
  subtitle: string;
  fetchKey: 'executive' | 'soc';
}

async function fetchDashboard(type: 'executive' | 'soc'): Promise<DashboardData> {
  try {
    return type === 'executive'
      ? await dashboardApi.getExecutive()
      : await dashboardApi.getSoc();
  } catch {
    return MOCK_DASHBOARD;
  }
}

export function DashboardView({ title, subtitle, fetchKey }: DashboardViewProps) {
  const { data, isLoading } = useQuery({
    queryKey: ['dashboard', fetchKey],
    queryFn: () => fetchDashboard(fetchKey),
  });

  const stats = data?.stats ?? MOCK_DASHBOARD.stats;

  return (
    <>
      <PageHeader title={title} subtitle={subtitle} />

      <StatCardsGrid>
        <StatCard
          title="Total Assets"
          value={stats.total_assets.toLocaleString()}
          icon={Storage}
          loading={isLoading}
        />
        <StatCard
          title="Open Vulnerabilities"
          value={stats.open_vulnerabilities.toLocaleString()}
          subtitle={`${stats.critical_vulnerabilities} critical · ${stats.high_vulnerabilities} high`}
          icon={BugReport}
          color="#ef4444"
          loading={isLoading}
        />
        <StatCard
          title="Compliance Score"
          value={`${stats.compliance_score}%`}
          icon={CheckCircle}
          color="#22c55e"
          trend={{ value: 2.3, label: 'vs last month' }}
          loading={isLoading}
        />
        <StatCard
          title="Overall Risk Score"
          value={stats.risk_score.toFixed(1)}
          subtitle={`MTTR: ${stats.mean_time_to_remediate_days} days`}
          icon={TrendingUp}
          color="#f97316"
          loading={isLoading}
        />
        {fetchKey === 'soc' && (
          <>
            <StatCard
              title="Active Scans"
              value={stats.active_scans}
              icon={Radar}
              loading={isLoading}
            />
            <StatCard
              title="Resolved This Month"
              value={stats.resolved_this_month}
              icon={CheckCircle}
              color="#22c55e"
              loading={isLoading}
            />
            <StatCard
              title="Critical Alerts"
              value={stats.critical_vulnerabilities}
              icon={Warning}
              color="#ef4444"
              loading={isLoading}
            />
          </>
        )}
      </StatCardsGrid>

      <Box
        sx={{
          display: 'grid',
          gridTemplateColumns: { xs: '1fr', md: 'repeat(2, 1fr)', xl: 'repeat(3, 1fr)' },
          gap: 2,
        }}
      >
        <Box sx={{ gridColumn: { md: 'span 1' } }}>
          <SeverityDistributionChart data={data?.severity_distribution ?? MOCK_DASHBOARD.severity_distribution} />
        </Box>
        <Box sx={{ gridColumn: { md: 'span 1', xl: 'span 2' } }}>
          <RiskTrendChart data={data?.risk_trends ?? MOCK_DASHBOARD.risk_trends} />
        </Box>
        <Box sx={{ gridColumn: { md: 'span 1' } }}>
          <RemediationProgressChart data={data?.remediation_progress ?? MOCK_DASHBOARD.remediation_progress} />
        </Box>
        <Box sx={{ gridColumn: { md: 'span 1' } }}>
          <RiskHeatmapChart data={data?.risk_heatmap ?? MOCK_DASHBOARD.risk_heatmap} />
        </Box>
        <Box sx={{ gridColumn: { md: 'span 1' } }}>
          <ComplianceScoreChart data={data?.compliance_scores ?? MOCK_DASHBOARD.compliance_scores} />
        </Box>
      </Box>
    </>
  );
}
