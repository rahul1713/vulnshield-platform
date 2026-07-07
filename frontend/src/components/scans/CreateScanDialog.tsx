'use client';

import {
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControl,
  InputLabel,
  MenuItem,
  Select,
  TextField,
} from '@mui/material';
import { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { assetsApi } from '@/lib/api';
import { ScanType } from '@/types';

const SCAN_TYPES: { value: ScanType; label: string }[] = [
  { value: 'agent', label: 'Agent-based' },
  { value: 'agentless_ssh', label: 'Agentless (SSH)' },
  { value: 'agentless_winrm', label: 'Agentless (WinRM)' },
  { value: 'network', label: 'Network' },
  { value: 'web_app', label: 'Web Application' },
  { value: 'cis_benchmark', label: 'CIS Benchmark' },
];

interface CreateScanDialogProps {
  open: boolean;
  onClose: () => void;
  onSubmit: (data: { name: string; scan_type: ScanType; target_asset_id?: string }) => Promise<void>;
}

export function CreateScanDialog({ open, onClose, onSubmit }: CreateScanDialogProps) {
  const [name, setName] = useState('');
  const [scanType, setScanType] = useState<ScanType>('network');
  const [assetId, setAssetId] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const { data: assets } = useQuery({
    queryKey: ['assets-for-scan'],
    queryFn: () => assetsApi.list({ page: 1, page_size: 50 }),
    enabled: open,
  });

  useEffect(() => {
    if (!open) {
      setName('');
      setScanType('network');
      setAssetId('');
      setSubmitting(false);
    }
  }, [open]);

  const handleSubmit = async () => {
    if (!name.trim()) return;
    setSubmitting(true);
    try {
      await onSubmit({
        name: name.trim(),
        scan_type: scanType,
        target_asset_id: assetId || undefined,
      });
      onClose();
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>New Vulnerability Scan</DialogTitle>
      <DialogContent sx={{ display: 'flex', flexDirection: 'column', gap: 2, pt: 1 }}>
        <TextField
          label="Scan name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
          fullWidth
          autoFocus
        />
        <FormControl fullWidth>
          <InputLabel>Scan type</InputLabel>
          <Select
            label="Scan type"
            value={scanType}
            onChange={(e) => setScanType(e.target.value as ScanType)}
          >
            {SCAN_TYPES.map((t) => (
              <MenuItem key={t.value} value={t.value}>
                {t.label}
              </MenuItem>
            ))}
          </Select>
        </FormControl>
        <FormControl fullWidth>
          <InputLabel>Target asset (optional)</InputLabel>
          <Select
            label="Target asset (optional)"
            value={assetId}
            onChange={(e) => setAssetId(e.target.value)}
          >
            <MenuItem value="">No specific asset</MenuItem>
            {(assets?.items ?? []).map((a) => (
              <MenuItem key={a.id} value={a.id}>
                {a.name} {a.ip_address ? `(${a.ip_address})` : ''}
              </MenuItem>
            ))}
          </Select>
        </FormControl>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={submitting}>
          Cancel
        </Button>
        <Button variant="contained" onClick={handleSubmit} disabled={submitting || !name.trim()}>
          {submitting ? 'Creating...' : 'Create Scan'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
