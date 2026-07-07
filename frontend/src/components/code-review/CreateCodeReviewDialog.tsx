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
  Tab,
  Tabs,
  TextField,
} from '@mui/material';
import { useEffect, useState } from 'react';

const LANGUAGES = ['Python', 'JavaScript', 'TypeScript', 'Java', 'Go', 'Ruby', 'C#', 'PHP', 'Rust', 'Kotlin'];

export type CodeReviewInput =
  | { mode: 'repository'; repository_url: string; language: string; branch?: string }
  | { mode: 'path'; file_path: string; language: string }
  | { mode: 'paste'; source_code: string; language: string; file_path?: string };

interface CreateCodeReviewDialogProps {
  open: boolean;
  onClose: () => void;
  onSubmit: (data: CodeReviewInput) => Promise<void>;
}

export function CreateCodeReviewDialog({ open, onClose, onSubmit }: CreateCodeReviewDialogProps) {
  const [tab, setTab] = useState(0);
  const [language, setLanguage] = useState('Python');
  const [repo, setRepo] = useState('https://github.com/org/repo');
  const [branch, setBranch] = useState('main');
  const [filePath, setFilePath] = useState('/workspace/src/app.py');
  const [sourceCode, setSourceCode] = useState('');
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (!open) {
      setTab(0);
      setLanguage('Python');
      setRepo('https://github.com/org/repo');
      setBranch('main');
      setFilePath('/workspace/src/app.py');
      setSourceCode('');
      setSubmitting(false);
    }
  }, [open]);

  const handleSubmit = async () => {
    setSubmitting(true);
    try {
      if (tab === 0) {
        if (!repo.trim()) return;
        await onSubmit({ mode: 'repository', repository_url: repo.trim(), language, branch });
      } else if (tab === 1) {
        if (!filePath.trim()) return;
        await onSubmit({ mode: 'path', file_path: filePath.trim(), language });
      } else {
        if (!sourceCode.trim()) return;
        await onSubmit({
          mode: 'paste',
          source_code: sourceCode,
          language,
          file_path: `submitted.${language.toLowerCase().slice(0, 2)}`,
        });
      }
      onClose();
    } finally {
      setSubmitting(false);
    }
  };

  const canSubmit =
    tab === 0 ? !!repo.trim() : tab === 1 ? !!filePath.trim() : sourceCode.trim().length > 10;

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="md">
      <DialogTitle>New Application Security Code Review</DialogTitle>
      <DialogContent sx={{ pt: 1 }}>
        <Tabs value={tab} onChange={(_, v) => setTab(v)} sx={{ mb: 2 }}>
          <Tab label="Repository URL" />
          <Tab label="Local File Path" />
          <Tab label="Paste Source Code" />
        </Tabs>

        <FormControl fullWidth sx={{ mb: 2 }}>
          <InputLabel>Language</InputLabel>
          <Select label="Language" value={language} onChange={(e) => setLanguage(e.target.value)}>
            {LANGUAGES.map((lang) => (
              <MenuItem key={lang} value={lang}>{lang}</MenuItem>
            ))}
          </Select>
        </FormControl>

        {tab === 0 && (
          <>
            <TextField
              label="Repository URL"
              value={repo}
              onChange={(e) => setRepo(e.target.value)}
              fullWidth
              margin="normal"
              placeholder="https://github.com/org/repo"
              helperText="For full repo scans, integrate with CI. Paste code or file path for immediate SAST."
            />
            <TextField
              label="Branch"
              value={branch}
              onChange={(e) => setBranch(e.target.value)}
              fullWidth
              margin="normal"
            />
          </>
        )}

        {tab === 1 && (
          <TextField
            label="Source file path"
            value={filePath}
            onChange={(e) => setFilePath(e.target.value)}
            fullWidth
            margin="normal"
            placeholder="/workspace/src/app.py"
            helperText="Path on the scanner host (Docker: /workspace, /app/code). Server reads file and runs SAST."
          />
        )}

        {tab === 2 && (
          <TextField
            label="Source code"
            value={sourceCode}
            onChange={(e) => setSourceCode(e.target.value)}
            fullWidth
            margin="normal"
            multiline
            minRows={12}
            placeholder={'# Paste code here for immediate static analysis\npassword = "secret"\n...'}
            helperText="Minimum 10 characters. Runs OWASP/CWE pattern checks and optional LLM deep analysis."
            sx={{ fontFamily: 'monospace' }}
          />
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={submitting}>Cancel</Button>
        <Button variant="contained" onClick={handleSubmit} disabled={submitting || !canSubmit}>
          {submitting ? 'Analyzing...' : 'Run SAST & Generate Report'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
