'use client';

import {
  Box,
  Drawer,
  IconButton,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Toolbar,
  Typography,
  useMediaQuery,
  useTheme,
  Divider,
} from '@mui/material';
import {
  ChevronLeft,
  ChevronRight,
  Shield,
} from '@mui/icons-material';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useMemo, useState } from 'react';
import { useAuth } from '@/components/layout/AuthProvider';
import { DRAWER_WIDTH, DRAWER_WIDTH_COLLAPSED } from '@/lib/theme';
import { filterNavItems, groupNavItems } from '@/lib/navigation';

interface SidebarProps {
  mobileOpen: boolean;
  onMobileClose: () => void;
}

export function Sidebar({ mobileOpen, onMobileClose }: SidebarProps) {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const pathname = usePathname();
  const { user, hasPermission } = useAuth();
  const [collapsed, setCollapsed] = useState(false);

  const navItems = useMemo(
    () => filterNavItems(hasPermission, user?.role),
    [hasPermission, user?.role]
  );
  const grouped = useMemo(() => groupNavItems(navItems), [navItems]);
  const drawerWidth = collapsed && !isMobile ? DRAWER_WIDTH_COLLAPSED : DRAWER_WIDTH;

  const drawerContent = (
    <Box className="flex h-full flex-col">
      <Toolbar
        sx={{
          px: collapsed && !isMobile ? 1 : 2,
          minHeight: { xs: 56, sm: 64 },
          borderBottom: 1,
          borderColor: 'divider',
        }}
      >
        <Shield sx={{ color: 'primary.main', fontSize: 32, mr: collapsed && !isMobile ? 0 : 1.5 }} />
        {(!collapsed || isMobile) && (
          <Box sx={{ flexGrow: 1 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, lineHeight: 1.2, color: 'primary.main' }}>
              VulnShield
            </Typography>
            <Typography variant="caption" color="text.secondary">
              Security Platform
            </Typography>
          </Box>
        )}
        {!isMobile && (
          <IconButton size="small" onClick={() => setCollapsed(!collapsed)}>
            {collapsed ? <ChevronRight /> : <ChevronLeft />}
          </IconButton>
        )}
      </Toolbar>

      <Box sx={{ flexGrow: 1, overflowY: 'auto', py: 1 }}>
        {Object.entries(grouped).map(([section, items]) => (
          <Box key={section} sx={{ mb: 1 }}>
            {(!collapsed || isMobile) && (
              <Typography
                variant="caption"
                sx={{
                  px: 2.5,
                  py: 0.5,
                  display: 'block',
                  color: 'text.secondary',
                  fontWeight: 600,
                  textTransform: 'uppercase',
                  letterSpacing: '0.08em',
                  fontSize: '0.65rem',
                }}
              >
                {section}
              </Typography>
            )}
            <List dense disablePadding>
              {items.map((item) => {
                const active = pathname === item.href || pathname.startsWith(`${item.href}/`);
                const Icon = item.icon;
                return (
                  <ListItemButton
                    key={item.href}
                    component={Link}
                    href={item.href}
                    selected={active}
                    onClick={isMobile ? onMobileClose : undefined}
                    sx={{
                      mx: 1,
                      mb: 0.25,
                      borderRadius: 1,
                      minHeight: 40,
                      justifyContent: collapsed && !isMobile ? 'center' : 'flex-start',
                      '&.Mui-selected': {
                        bgcolor: 'primary.main',
                        color: 'primary.contrastText',
                        '& .MuiListItemIcon-root': { color: 'primary.contrastText' },
                        '&:hover': { bgcolor: 'primary.dark' },
                      },
                    }}
                  >
                    <ListItemIcon
                      sx={{
                        minWidth: collapsed && !isMobile ? 0 : 36,
                        justifyContent: 'center',
                        color: active ? 'inherit' : 'text.secondary',
                      }}
                    >
                      <Icon fontSize="small" />
                    </ListItemIcon>
                    {(!collapsed || isMobile) && (
                      <ListItemText
                        primary={item.title}
                        primaryTypographyProps={{ fontSize: '0.875rem', fontWeight: active ? 600 : 400 }}
                      />
                    )}
                  </ListItemButton>
                );
              })}
            </List>
            <Divider sx={{ my: 0.5, mx: 2 }} />
          </Box>
        ))}
      </Box>
    </Box>
  );

  if (isMobile) {
    return (
      <Drawer
        variant="temporary"
        open={mobileOpen}
        onClose={onMobileClose}
        ModalProps={{ keepMounted: true }}
        sx={{ '& .MuiDrawer-paper': { width: DRAWER_WIDTH } }}
      >
        {drawerContent}
      </Drawer>
    );
  }

  return (
    <Drawer
      variant="permanent"
      sx={{
        width: drawerWidth,
        flexShrink: 0,
        '& .MuiDrawer-paper': {
          width: drawerWidth,
          boxSizing: 'border-box',
          transition: theme.transitions.create('width', {
            easing: theme.transitions.easing.sharp,
            duration: theme.transitions.duration.enteringScreen,
          }),
          overflowX: 'hidden',
        },
      }}
    >
      {drawerContent}
    </Drawer>
  );
}

export { DRAWER_WIDTH };
