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
} from '@mui/material';
import { Save } from '@mui/icons-material';
import { PageHeader } from '@/components/ui/PageHeader';
import { useThemeMode } from '@/components/layout/ThemeProvider';
import { useToast } from '@/components/ui/ToastProvider';

export default function SettingsPage() {
  const { mode, setMode } = useThemeMode();
  const { showToast } = useToast();

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
            <Typography variant="h6" gutterBottom>API Configuration</Typography>
            <TextField
              fullWidth
              label="API URL"
              value={process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080/api/v1'}
              disabled
              margin="normal"
              helperText="Configured via NEXT_PUBLIC_API_URL environment variable"
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
