'use client';

import { useState } from 'react';
import {
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  TextField,
} from '@mui/material';

interface StartWebScanDialogProps {
  open: boolean;
  onClose: () => void;
  onSubmit: (url: string) => Promise<void>;
}

export function StartWebScanDialog({ open, onClose, onSubmit }: StartWebScanDialogProps) {
  const [url, setUrl] = useState('https://');
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async () => {
    if (!url.trim() || url === 'https://') return;
    setSubmitting(true);
    try {
      await onSubmit(url.trim());
      onClose();
      setUrl('https://');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>Start Web Application Scan</DialogTitle>
      <DialogContent>
        <TextField
          label="Target URL"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          fullWidth
          margin="normal"
          placeholder="https://example.com"
          helperText="Active DAST scan will crawl and test the target for OWASP Top 10 issues."
        />
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" onClick={handleSubmit} disabled={submitting}>
          {submitting ? 'Starting...' : 'Start Scan'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
