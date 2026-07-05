'use client';

import { Card, CardContent, Typography, Box, useTheme } from '@mui/material';
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  BarChart,
  Bar,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar,
} from 'recharts';
import {
  SeverityDistribution,
  RiskTrendPoint,
  RemediationProgress,
  HeatmapCell,
  ComplianceScorePoint,
} from '@/types';
import { SEVERITY_COLORS } from '@/lib/theme';

interface ChartCardProps {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
  height?: number;
}

function ChartCard({ title, subtitle, children, height = 300 }: ChartCardProps) {
  return (
    <Card sx={{ height: '100%' }}>
      <CardContent>
        <Typography variant="h6" gutterBottom>
          {title}
        </Typography>
        {subtitle && (
          <Typography variant="caption" color="text.secondary" display="block" sx={{ mb: 2 }}>
            {subtitle}
          </Typography>
        )}
        <Box sx={{ width: '100%', height }}>{children}</Box>
      </CardContent>
    </Card>
  );
}

export function SeverityDistributionChart({ data }: { data: SeverityDistribution[] }) {
  const theme = useTheme();
  return (
    <ChartCard title="Severity Distribution" subtitle="Open vulnerabilities by severity">
      <ResponsiveContainer>
        <PieChart>
          <Pie
            data={data}
            dataKey="count"
            nameKey="severity"
            cx="50%"
            cy="50%"
            innerRadius={60}
            outerRadius={100}
            paddingAngle={2}
            label={({ severity, count }) => `${severity}: ${count}`}
          >
            {data.map((entry) => (
              <Cell key={entry.severity} fill={SEVERITY_COLORS[entry.severity]} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              backgroundColor: theme.palette.background.paper,
              border: `1px solid ${theme.palette.divider}`,
              borderRadius: 8,
            }}
          />
          <Legend />
        </PieChart>
      </ResponsiveContainer>
    </ChartCard>
  );
}

export function RiskTrendChart({ data }: { data: RiskTrendPoint[] }) {
  const theme = useTheme();
  return (
    <ChartCard title="Risk Trends" subtitle="6-month vulnerability trend" height={320}>
      <ResponsiveContainer>
        <LineChart data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke={theme.palette.divider} />
          <XAxis dataKey="date" stroke={theme.palette.text.secondary} fontSize={12} />
          <YAxis stroke={theme.palette.text.secondary} fontSize={12} />
          <Tooltip
            contentStyle={{
              backgroundColor: theme.palette.background.paper,
              border: `1px solid ${theme.palette.divider}`,
              borderRadius: 8,
            }}
          />
          <Legend />
          <Line type="monotone" dataKey="critical" stroke={SEVERITY_COLORS.critical} strokeWidth={2} dot={false} />
          <Line type="monotone" dataKey="high" stroke={SEVERITY_COLORS.high} strokeWidth={2} dot={false} />
          <Line type="monotone" dataKey="overall_risk" stroke={theme.palette.primary.main} strokeWidth={2} strokeDasharray="5 5" dot={false} />
        </LineChart>
      </ResponsiveContainer>
    </ChartCard>
  );
}

export function RemediationProgressChart({ data }: { data: RemediationProgress[] }) {
  const theme = useTheme();
  return (
    <ChartCard title="Remediation Progress" subtitle="Opened vs resolved per month">
      <ResponsiveContainer>
        <BarChart data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke={theme.palette.divider} />
          <XAxis dataKey="month" stroke={theme.palette.text.secondary} fontSize={12} />
          <YAxis stroke={theme.palette.text.secondary} fontSize={12} />
          <Tooltip
            contentStyle={{
              backgroundColor: theme.palette.background.paper,
              border: `1px solid ${theme.palette.divider}`,
              borderRadius: 8,
            }}
          />
          <Legend />
          <Bar dataKey="opened" fill={SEVERITY_COLORS.high} radius={[4, 4, 0, 0]} />
          <Bar dataKey="resolved" fill={SEVERITY_COLORS.low} radius={[4, 4, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  );
}

export function RiskHeatmapChart({ data }: { data: HeatmapCell[] }) {
  const theme = useTheme();
  const assets = Array.from(new Set(data.map((d) => d.asset)));
  const categories = Array.from(new Set(data.map((d) => d.category)));

  const heatmapData = assets.map((asset) => {
    const row: Record<string, string | number> = { asset };
    categories.forEach((cat) => {
      const cell = data.find((d) => d.asset === asset && d.category === cat);
      row[cat] = cell?.value ?? 0;
    });
    return row;
  });

  return (
    <ChartCard title="Risk Heatmap" subtitle="Asset risk by vulnerability category" height={320}>
      <ResponsiveContainer>
        <BarChart data={heatmapData} layout="vertical">
          <CartesianGrid strokeDasharray="3 3" stroke={theme.palette.divider} />
          <XAxis type="number" domain={[0, 100]} stroke={theme.palette.text.secondary} fontSize={12} />
          <YAxis type="category" dataKey="asset" width={100} stroke={theme.palette.text.secondary} fontSize={11} />
          <Tooltip
            contentStyle={{
              backgroundColor: theme.palette.background.paper,
              border: `1px solid ${theme.palette.divider}`,
              borderRadius: 8,
            }}
          />
          <Legend />
          {categories.map((cat, i) => (
            <Bar
              key={cat}
              dataKey={cat}
              stackId="a"
              fill={[SEVERITY_COLORS.critical, SEVERITY_COLORS.high, SEVERITY_COLORS.medium, SEVERITY_COLORS.low, theme.palette.primary.main][i % 5]}
            />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  );
}

export function ComplianceScoreChart({ data }: { data: ComplianceScorePoint[] }) {
  const theme = useTheme();
  return (
    <ChartCard title="Compliance Scores" subtitle="Framework assessment results">
      <ResponsiveContainer>
        <RadarChart data={data}>
          <PolarGrid stroke={theme.palette.divider} />
          <PolarAngleAxis dataKey="framework" tick={{ fill: theme.palette.text.secondary, fontSize: 11 }} />
          <PolarRadiusAxis angle={30} domain={[0, 100]} tick={{ fill: theme.palette.text.secondary, fontSize: 10 }} />
          <Radar
            name="Score"
            dataKey="score"
            stroke={theme.palette.primary.main}
            fill={theme.palette.primary.main}
            fillOpacity={0.3}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: theme.palette.background.paper,
              border: `1px solid ${theme.palette.divider}`,
              borderRadius: 8,
            }}
          />
        </RadarChart>
      </ResponsiveContainer>
    </ChartCard>
  );
}
