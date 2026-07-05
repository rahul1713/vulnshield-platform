'use client';

import {
  AppBar,
  Avatar,
  Box,
  IconButton,
  InputAdornment,
  List,
  ListItem,
  ListItemButton,
  ListItemText,
  Menu,
  MenuItem,
  Paper,
  Popper,
  TextField,
  Toolbar,
  Tooltip,
  Typography,
  useMediaQuery,
  useTheme,
  ClickAwayListener,
} from '@mui/material';
import {
  DarkMode,
  LightMode,
  Logout,
  Menu as MenuIcon,
  NotificationsNone,
  Search,
} from '@mui/icons-material';
import { useRouter } from 'next/navigation';
import { useCallback, useRef, useState } from 'react';
import { useAuth } from '@/components/layout/AuthProvider';
import { useThemeMode } from '@/components/layout/ThemeProvider';
import { searchApi } from '@/lib/api';
import { MOCK_SEARCH } from '@/lib/mock-data';
import { SearchResult } from '@/types';
import { DRAWER_WIDTH } from '@/lib/theme';

interface HeaderProps {
  onMenuClick: () => void;
  sidebarWidth?: number;
}

export function Header({ onMenuClick, sidebarWidth = DRAWER_WIDTH }: HeaderProps) {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const { user, logout } = useAuth();
  const { mode, toggleTheme } = useThemeMode();
  const router = useRouter();
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<SearchResult[]>([]);
  const [searchOpen, setSearchOpen] = useState(false);
  const searchRef = useRef<HTMLDivElement>(null);

  const handleSearch = useCallback(async (query: string) => {
    setSearchQuery(query);
    if (query.length < 2) {
      setSearchResults([]);
      setSearchOpen(false);
      return;
    }
    try {
      const results = await searchApi.search(query);
      setSearchResults(results);
    } catch {
      const filtered = MOCK_SEARCH.filter(
        (r) =>
          r.title.toLowerCase().includes(query.toLowerCase()) ||
          r.subtitle?.toLowerCase().includes(query.toLowerCase())
      );
      setSearchResults(filtered);
    }
    setSearchOpen(true);
  }, []);

  const handleResultClick = (result: SearchResult) => {
    setSearchOpen(false);
    setSearchQuery('');
    router.push(result.href);
  };

  const handleLogout = async () => {
    setAnchorEl(null);
    await logout();
    router.push('/login');
  };

  const initials = user
    ? `${user.first_name?.[0] || ''}${user.last_name?.[0] || user.username[0]}`.toUpperCase()
    : '?';

  return (
    <AppBar
      position="fixed"
      elevation={0}
      sx={{
        width: isMobile ? '100%' : `calc(100% - ${sidebarWidth}px)`,
        ml: isMobile ? 0 : `${sidebarWidth}px`,
        bgcolor: 'background.paper',
        borderBottom: 1,
        borderColor: 'divider',
      }}
    >
      <Toolbar sx={{ gap: 2 }}>
        {isMobile && (
          <IconButton edge="start" onClick={onMenuClick} color="inherit">
            <MenuIcon />
          </IconButton>
        )}

        <Box ref={searchRef} sx={{ flexGrow: 1, maxWidth: 480, position: 'relative' }}>
          <TextField
            size="small"
            fullWidth
            placeholder="Search assets, vulnerabilities, CVEs..."
            value={searchQuery}
            onChange={(e) => handleSearch(e.target.value)}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <Search fontSize="small" color="action" />
                </InputAdornment>
              ),
              sx: { bgcolor: 'action.hover', borderRadius: 2 },
            }}
          />
          <Popper open={searchOpen && searchResults.length > 0} anchorEl={searchRef.current} placement="bottom-start" sx={{ zIndex: 1400, width: searchRef.current?.offsetWidth }}>
            <ClickAwayListener onClickAway={() => setSearchOpen(false)}>
              <Paper elevation={8} sx={{ mt: 1, maxHeight: 320, overflow: 'auto' }}>
                <List dense>
                  {searchResults.map((result) => (
                    <ListItem key={`${result.type}-${result.id}`} disablePadding>
                      <ListItemButton onClick={() => handleResultClick(result)}>
                        <ListItemText
                          primary={result.title}
                          secondary={`${result.type} · ${result.subtitle || ''}`}
                        />
                      </ListItemButton>
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </ClickAwayListener>
          </Popper>
        </Box>

        <Tooltip title="Notifications">
          <IconButton color="inherit">
            <NotificationsNone />
          </IconButton>
        </Tooltip>

        <Tooltip title={mode === 'dark' ? 'Light mode' : 'Dark mode'}>
          <IconButton onClick={toggleTheme} color="inherit">
            {mode === 'dark' ? <LightMode /> : <DarkMode />}
          </IconButton>
        </Tooltip>

        <IconButton onClick={(e) => setAnchorEl(e.currentTarget)} sx={{ p: 0.5 }}>
          <Avatar sx={{ width: 36, height: 36, bgcolor: 'primary.main', fontSize: '0.875rem' }}>
            {initials}
          </Avatar>
        </IconButton>

        <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={() => setAnchorEl(null)}>
          <Box sx={{ px: 2, py: 1, minWidth: 200 }}>
            <Typography variant="subtitle2">{user?.first_name} {user?.last_name}</Typography>
            <Typography variant="caption" color="text.secondary">{user?.email}</Typography>
            <Typography variant="caption" display="block" color="primary.main" sx={{ mt: 0.5, textTransform: 'capitalize' }}>
              {user?.role?.replace('_', ' ')}
            </Typography>
          </Box>
          <MenuItem onClick={handleLogout}>
            <Logout fontSize="small" sx={{ mr: 1 }} /> Sign out
          </MenuItem>
        </Menu>
      </Toolbar>
    </AppBar>
  );
}
