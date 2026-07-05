'use client';

import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  CircularProgress,
  TextField,
  Typography,
} from '@mui/material';
import { Shield, LockOutlined } from '@mui/icons-material';
import { useRouter } from 'next/navigation';
import { FormEvent, useEffect, useState } from 'react';
import { useAuth } from '@/components/layout/AuthProvider';

export default function LoginPage() {
  const { login, isAuthenticated, isLoading } = useAuth();
  const router = useRouter();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (!isLoading && isAuthenticated) {
      router.replace('/dashboard');
    }
  }, [isAuthenticated, isLoading, router]);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError('');
    setSubmitting(true);
    try {
      await login({ username, password });
      router.replace('/dashboard');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed. Please check your credentials.');
    } finally {
      setSubmitting(false);
    }
  };

  if (isLoading) {
    return (
      <Box className="flex min-h-screen items-center justify-center bg-surface-dark">
        <CircularProgress color="primary" />
      </Box>
    );
  }

  return (
    <Box
      className="flex min-h-screen items-center justify-center p-4"
      sx={{
        background: 'linear-gradient(135deg, #0a0e17 0%, #111827 50%, #0e7490 100%)',
      }}
    >
      <Box className="w-full max-w-md">
        <Box className="mb-8 text-center">
          <Box className="mb-4 inline-flex items-center justify-center rounded-2xl bg-cyan-500/10 p-4">
            <Shield sx={{ fontSize: 48, color: 'primary.main' }} />
          </Box>
          <Typography variant="h4" sx={{ fontWeight: 700, color: 'white', mb: 1 }}>
            VulnShield
          </Typography>
          <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.6)' }}>
            Enterprise Vulnerability Management Platform
          </Typography>
        </Box>

        <Card sx={{ bgcolor: 'background.paper' }}>
          <CardContent sx={{ p: 4 }}>
            <Box className="mb-6 flex items-center gap-2">
              <LockOutlined color="primary" />
              <Typography variant="h6">Sign in to your account</Typography>
            </Box>

            {error && (
              <Alert severity="error" sx={{ mb: 3 }}>
                {error}
              </Alert>
            )}

            <Box component="form" onSubmit={handleSubmit}>
              <TextField
                fullWidth
                label="Username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                margin="normal"
                required
                autoFocus
                autoComplete="username"
              />
              <TextField
                fullWidth
                label="Password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                margin="normal"
                required
                autoComplete="current-password"
              />
              <Button
                type="submit"
                fullWidth
                variant="contained"
                size="large"
                disabled={submitting}
                sx={{ mt: 3, py: 1.5 }}
              >
                {submitting ? <CircularProgress size={24} color="inherit" /> : 'Sign In'}
              </Button>
            </Box>

            <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 3, textAlign: 'center' }}>
              Default: admin / Admin@123456
            </Typography>
          </CardContent>
        </Card>
      </Box>
    </Box>
  );
}
