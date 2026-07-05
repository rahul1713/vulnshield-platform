import { PaletteMode } from '@mui/material';

export const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
  info: '#06b6d4',
};

export const getDesignTokens = (mode: PaletteMode) => ({
  palette: {
    mode,
    primary: {
      main: mode === 'dark' ? '#22d3ee' : '#0891b2',
      light: mode === 'dark' ? '#67e8f9' : '#22d3ee',
      dark: mode === 'dark' ? '#0891b2' : '#0e7490',
      contrastText: mode === 'dark' ? '#0a0e17' : '#ffffff',
    },
    secondary: {
      main: mode === 'dark' ? '#3b82f6' : '#2563eb',
      light: '#60a5fa',
      dark: '#1d4ed8',
    },
    error: { main: '#ef4444' },
    warning: { main: '#f97316' },
    info: { main: '#06b6d4' },
    success: { main: '#22c55e' },
    background: {
      default: mode === 'dark' ? '#0a0e17' : '#f1f5f9',
      paper: mode === 'dark' ? '#111827' : '#ffffff',
    },
    text: {
      primary: mode === 'dark' ? '#f1f5f9' : '#0f172a',
      secondary: mode === 'dark' ? '#94a3b8' : '#64748b',
    },
    divider: mode === 'dark' ? '#1e293b' : '#e2e8f0',
  },
  typography: {
    fontFamily: '"Inter", "Roboto", "Helvetica", "Arial", sans-serif',
    h4: { fontWeight: 700, letterSpacing: '-0.02em' },
    h5: { fontWeight: 600 },
    h6: { fontWeight: 600 },
    subtitle2: { fontWeight: 500, letterSpacing: '0.02em' },
  },
  shape: { borderRadius: 8 },
  components: {
    MuiCssBaseline: {
      styleOverrides: {
        body: {
          scrollbarColor: mode === 'dark' ? '#334155 #0a0e17' : '#cbd5e1 #f1f5f9',
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: {
          textTransform: 'none' as const,
          fontWeight: 600,
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
          border: mode === 'dark' ? '1px solid #1e293b' : '1px solid #e2e8f0',
        },
      },
    },
    MuiDrawer: {
      styleOverrides: {
        paper: {
          backgroundImage: 'none',
          borderRight: mode === 'dark' ? '1px solid #1e293b' : '1px solid #e2e8f0',
        },
      },
    },
    MuiTableCell: {
      styleOverrides: {
        head: {
          fontWeight: 600,
          backgroundColor: mode === 'dark' ? '#1a2332' : '#f8fafc',
        },
      },
    },
    MuiChip: {
      styleOverrides: {
        root: { fontWeight: 500 },
      },
    },
  },
});

export const DRAWER_WIDTH = 260;
export const DRAWER_WIDTH_COLLAPSED = 72;
