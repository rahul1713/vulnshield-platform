'use client';

import { Box, Card, CardContent, Typography, Skeleton } from '@mui/material';
import { SvgIconComponent } from '@mui/icons-material';

export interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon?: SvgIconComponent;
  trend?: { value: number; label: string };
  color?: string;
  loading?: boolean;
}

export function StatCard({ title, value, subtitle, icon: Icon, trend, color, loading }: StatCardProps) {
  if (loading) {
    return (
      <Card>
        <CardContent>
          <Skeleton width="60%" />
          <Skeleton width="40%" height={40} sx={{ my: 1 }} />
          <Skeleton width="80%" />
        </CardContent>
      </Card>
    );
  }

  return (
    <Card sx={{ height: '100%' }}>
      <CardContent>
        <Box className="flex items-start justify-between">
          <Box>
            <Typography variant="body2" color="text.secondary" gutterBottom>
              {title}
            </Typography>
            <Typography variant="h4" sx={{ fontWeight: 700, color: color || 'text.primary' }}>
              {value}
            </Typography>
            {subtitle && (
              <Typography variant="caption" color="text.secondary">
                {subtitle}
              </Typography>
            )}
            {trend && (
              <Typography
                variant="caption"
                sx={{ display: 'block', mt: 0.5, color: trend.value >= 0 ? 'success.main' : 'error.main' }}
              >
                {trend.value >= 0 ? '↑' : '↓'} {Math.abs(trend.value)}% {trend.label}
              </Typography>
            )}
          </Box>
          {Icon && (
            <Box
              sx={{
                p: 1,
                borderRadius: 2,
                bgcolor: 'action.hover',
                color: color || 'primary.main',
              }}
            >
              <Icon />
            </Box>
          )}
        </Box>
      </CardContent>
    </Card>
  );
}

interface StatCardsGridProps {
  children: React.ReactNode;
}

export function StatCardsGrid({ children }: StatCardsGridProps) {
  return (
    <Box
      sx={{
        display: 'grid',
        gridTemplateColumns: {
          xs: '1fr',
          sm: 'repeat(2, 1fr)',
          lg: 'repeat(4, 1fr)',
        },
        gap: 2,
        mb: 3,
      }}
    >
      {children}
    </Box>
  );
}
