'use client';

import { Chip } from '@mui/material';
import { SEVERITY_COLORS } from '@/lib/theme';
import { SEVERITY_LABELS } from '@/lib/navigation';

interface SeverityChipProps {
  severity: string;
  size?: 'small' | 'medium';
}

export function SeverityChip({ severity, size = 'small' }: SeverityChipProps) {
  const color = SEVERITY_COLORS[severity] || '#64748b';
  return (
    <Chip
      label={SEVERITY_LABELS[severity] || severity}
      size={size}
      sx={{
        bgcolor: `${color}20`,
        color,
        borderColor: `${color}40`,
        border: '1px solid',
        fontWeight: 600,
        textTransform: 'capitalize',
      }}
    />
  );
}

interface StatusChipProps {
  status: string;
  size?: 'small' | 'medium';
}

export function StatusChip({ status, size = 'small' }: StatusChipProps) {
  const label = status.replace(/_/g, ' ');
  return (
    <Chip
      label={label}
      size={size}
      variant="outlined"
      sx={{ textTransform: 'capitalize', fontWeight: 500 }}
    />
  );
}

export function SimulatedBadge() {
  return (
    <Chip
      label="Simulated"
      size="small"
      variant="outlined"
      color="warning"
      sx={{ ml: 0.75, fontSize: '0.65rem', height: 20, fontWeight: 500 }}
    />
  );
}
