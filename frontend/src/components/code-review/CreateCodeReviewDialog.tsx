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

const LANGUAGES = ['Python', 'JavaScript', 'TypeScript', 'Java', 'Go', 'Ruby', 'C#', 'PHP'];

interface CreateCodeReviewDialogProps {
  open: boolean;
  onClose: () => void;
  onSubmit: (repo: string, language: string) => Promise<void>;
}

export function CreateCodeReviewDialog({ open, onClose, onSubmit }: CreateCodeReviewDialogProps) {
  const [repo, setRepo] = useState('https://github.com/org/repo');
  const [language, setLanguage] = useState('Python');
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (!open) {
      setRepo('https://github.com/org/repo');
      setLanguage('Python');
      setSubmitting(false);
    }
  }, [open]);

  const handleSubmit = async () => {
    if (!repo.trim()) return;
    setSubmitting(true);
    try {
      await onSubmit(repo.trim(), language);
      onClose();
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>New AI Code Review</DialogTitle>
      <DialogContent sx={{ display: 'flex', flexDirection: 'column', gap: 2, pt: 1 }}>
        <TextField
          label="Repository URL"
          value={repo}
          onChange={(e) => setRepo(e.target.value)}
          fullWidth
          required
          autoFocus
        />
        <FormControl fullWidth>
          <InputLabel>Primary language</InputLabel>
          <Select label="Primary language" value={language} onChange={(e) => setLanguage(e.target.value)}>
            {LANGUAGES.map((lang) => (
              <MenuItem key={lang} value={lang}>
                {lang}
              </MenuItem>
            ))}
          </Select>
        </FormControl>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={submitting}>
          Cancel
        </Button>
        <Button variant="contained" onClick={handleSubmit} disabled={submitting || !repo.trim()}>
          {submitting ? 'Starting...' : 'Start Review'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
