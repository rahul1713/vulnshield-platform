'use client';

import { Alert, Box, Toolbar } from '@mui/material';
import { useState } from 'react';
import { Sidebar } from './Sidebar';
import { Header } from './Header';
import { ProtectedRoute } from './ProtectedRoute';
import { DRAWER_WIDTH } from '@/lib/theme';
import { isSandboxDeploy } from '@/lib/env';

export function DashboardLayout({ children }: { children: React.ReactNode }) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const showSandboxBanner = isSandboxDeploy();

  return (
    <ProtectedRoute>
      <Box className="flex min-h-screen">
        <Sidebar mobileOpen={mobileOpen} onMobileClose={() => setMobileOpen(false)} />
        <Box
          component="main"
          sx={{
            flexGrow: 1,
            width: { md: `calc(100% - ${DRAWER_WIDTH}px)` },
            minHeight: '100vh',
            bgcolor: 'background.default',
          }}
        >
          <Header onMenuClick={() => setMobileOpen(true)} />
          <Toolbar />
          {showSandboxBanner && (
            <Alert severity="warning" sx={{ mx: { xs: 2, sm: 3 }, mb: 2 }}>
              Sandbox mode — scans restricted to allowlisted targets (localhost, *.local,
              docker-internal). No external scanning or simulated findings.
            </Alert>
          )}
          <Box sx={{ p: { xs: 2, sm: 3 } }}>{children}</Box>
        </Box>
      </Box>
    </ProtectedRoute>
  );
}
