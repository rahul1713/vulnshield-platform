'use client';

import {
  Box,
  Button,
  Drawer,
  FormControl,
  InputLabel,
  MenuItem,
  Select,
  Typography,
} from '@mui/material';
import { SeverityChip } from '@/components/ui/SeverityChip';
import { Vulnerability, VulnStatus } from '@/types';

const STATUSES: VulnStatus[] = [
  'open', 'acknowledged', 'assigned', 'in_progress', 'risk_accepted',
  'mitigated', 'resolved', 'closed', 'false_positive',
];

interface VulnDetailDrawerProps {
  vuln: Vulnerability | null;
  open: boolean;
  onClose: () => void;
  onStatusChange: (id: string, status: VulnStatus) => Promise<void>;
}

export function VulnDetailDrawer({ vuln, open, onClose, onStatusChange }: VulnDetailDrawerProps) {
  if (!vuln) return null;

  return (
    <Drawer anchor="right" open={open} onClose={onClose} PaperProps={{ sx: { width: { xs: '100%', sm: 420 }, p: 3 } }}>
      <Typography variant="h6" gutterBottom>
        {vuln.title}
      </Typography>
      <Box sx={{ mb: 2 }}>
        <SeverityChip severity={vuln.severity} />
      </Box>
      {vuln.cve_identifier && (
        <Typography variant="body2" color="text.secondary" gutterBottom>
          {vuln.cve_identifier}
        </Typography>
      )}
      {vuln.asset_name && (
        <Typography variant="body2" gutterBottom>
          Asset: <strong>{vuln.asset_name}</strong>
        </Typography>
      )}
      {vuln.description && (
        <Typography variant="body2" sx={{ mt: 2, mb: 2 }}>
          {vuln.description}
        </Typography>
      )}
      {vuln.remediation && (
        <Box sx={{ mt: 2, p: 2, bgcolor: 'action.hover', borderRadius: 1 }}>
          <Typography variant="subtitle2">Remediation</Typography>
          <Typography variant="body2">{vuln.remediation}</Typography>
        </Box>
      )}
      <FormControl fullWidth sx={{ mt: 3 }}>
        <InputLabel>Status</InputLabel>
        <Select
          label="Status"
          value={vuln.status}
          onChange={async (e) => {
            await onStatusChange(vuln.id, e.target.value as VulnStatus);
          }}
        >
          {STATUSES.map((s) => (
            <MenuItem key={s} value={s}>
              {s.replace(/_/g, ' ')}
            </MenuItem>
          ))}
        </Select>
      </FormControl>
      <Button sx={{ mt: 3 }} variant="outlined" fullWidth onClick={onClose}>
        Close
      </Button>
    </Drawer>
  );
}
