'use client';

import {
  Box,
  Card,
  CardContent,
  Divider,
  FormControlLabel,
  Switch,
  TextField,
  Typography,
  Button,
  Chip,
  Stack,
} from '@mui/material';
import { Save } from '@mui/icons-material';
import { PageHeader } from '@/components/ui/PageHeader';
import { useThemeMode } from '@/components/layout/ThemeProvider';
import { useToast } from '@/components/ui/ToastProvider';
import { getApiUrl, isSandboxDeploy } from '@/lib/env';

export default function SettingsPage() {
  const { mode, setMode } = useThemeMode();
  const { showToast } = useToast();
  const apiUrl = getApiUrl();

  const handleSave = () => {
    showToast('Preferences saved (theme persists automatically)', 'success');
  };

  return (
    <>
      <PageHeader title="Settings" subtitle="Platform configuration and preferences" />

      <Box sx={{ display: 'grid', gap: 3, maxWidth: 720 }}>
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>Appearance</Typography>
            <FormControlLabel
              control={
                <Switch
                  checked={mode === 'dark'}
                  onChange={(_, checked) => setMode(checked ? 'dark' : 'light')}
                />
              }
              label="Dark mode"
            />
          </CardContent>
        </Card>

        <Card>
          <CardContent>
            <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1 }}>
              <Typography variant="h6">API Configuration</Typography>
              {isSandboxDeploy() && <Chip label="Sandbox" size="small" color="info" />}
            </Stack>
            <TextField
              fullWidth
              label="API URL"
              value={apiUrl}
              disabled
              margin="normal"
              helperText={
                isSandboxDeploy()
                  ? 'Sandbox API gateway — derived from your browser host and port 18080'
                  : 'Configured via NEXT_PUBLIC_API_URL environment variable'
              }
            />
          </CardContent>
        </Card>

        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>Notifications</Typography>
            <FormControlLabel control={<Switch defaultChecked />} label="Email alerts for critical vulnerabilities" />
            <Divider sx={{ my: 2 }} />
            <FormControlLabel control={<Switch />} label="Slack integration" />
            <Divider sx={{ my: 2 }} />
            <FormControlLabel control={<Switch />} label="Microsoft Teams integration" />
          </CardContent>
        </Card>

        <Box>
          <Button variant="contained" startIcon={<Save />} onClick={handleSave}>Save Preferences</Button>
        </Box>
      </Box>
    </>
  );
}
