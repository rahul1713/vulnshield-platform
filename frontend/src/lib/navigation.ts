import {
  Code,
  Dashboard,
  Description,
  Gavel,
  History,
  People,
  Radar,
  Security,
  Settings,
  Shield,
  Storage,
  TrendingUp,
  Web,
  BugReport,
} from '@mui/icons-material';
import { SvgIconComponent } from '@mui/icons-material';

export interface NavItem {
  title: string;
  href: string;
  icon: SvgIconComponent;
  permissions?: string[];
  roles?: string[];
  section?: string;
}

export const NAV_ITEMS: NavItem[] = [
  {
    title: 'Executive Dashboard',
    href: '/dashboard',
    icon: Dashboard,
    permissions: ['dashboard:read'],
    section: 'Overview',
  },
  {
    title: 'SOC Dashboard',
    href: '/soc',
    icon: Radar,
    permissions: ['dashboard:read'],
    section: 'Overview',
  },
  {
    title: 'Assets',
    href: '/assets',
    icon: Storage,
    permissions: ['assets:read'],
    section: 'Inventory',
  },
  {
    title: 'Vulnerabilities',
    href: '/vulnerabilities',
    icon: BugReport,
    permissions: ['vulnerabilities:read'],
    section: 'Security',
  },
  {
    title: 'Scans',
    href: '/scans',
    icon: Radar,
    permissions: ['scans:read'],
    section: 'Security',
  },
  {
    title: 'Web Scanner',
    href: '/web-scanner',
    icon: Web,
    permissions: ['scans:read'],
    section: 'Security',
  },
  {
    title: 'Code Review',
    href: '/code-review',
    icon: Code,
    permissions: ['codereview:read'],
    section: 'Security',
  },
  {
    title: 'Red Team',
    href: '/red-team',
    icon: Security,
    permissions: ['redteam:read'],
    section: 'Security',
  },
  {
    title: 'Compliance',
    href: '/compliance',
    icon: Gavel,
    permissions: ['compliance:read'],
    section: 'Governance',
  },
  {
    title: 'Reports',
    href: '/reports',
    icon: Description,
    permissions: ['reports:read'],
    section: 'Governance',
  },
  {
    title: 'Patch Intelligence',
    href: '/patch-intelligence',
    icon: Shield,
    permissions: ['vulnerabilities:read'],
    section: 'Intelligence',
  },
  {
    title: 'Risk',
    href: '/risk',
    icon: TrendingUp,
    permissions: ['dashboard:read'],
    section: 'Intelligence',
  },
  {
    title: 'Settings',
    href: '/settings',
    icon: Settings,
    section: 'Administration',
  },
  {
    title: 'Users',
    href: '/users',
    icon: People,
    permissions: ['users:read'],
    section: 'Administration',
  },
  {
    title: 'Audit Logs',
    href: '/audit-logs',
    icon: History,
    permissions: ['audit:read'],
    section: 'Administration',
  },
];

export function filterNavItems(
  hasPermission: (p: string) => boolean,
  role?: string
): NavItem[] {
  return NAV_ITEMS.filter((item) => {
    if (item.roles && role && !item.roles.includes(role)) return false;
    if (!item.permissions || item.permissions.length === 0) return true;
    return item.permissions.some((p) => hasPermission(p));
  });
}

export function groupNavItems(items: NavItem[]): Record<string, NavItem[]> {
  return items.reduce<Record<string, NavItem[]>>((acc, item) => {
    const section = item.section || 'Other';
    if (!acc[section]) acc[section] = [];
    acc[section].push(item);
    return acc;
  }, {});
}

export const SEVERITY_LABELS: Record<string, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};

export const STATUS_COLORS: Record<string, 'error' | 'warning' | 'info' | 'success' | 'default'> = {
  open: 'error',
  acknowledged: 'warning',
  assigned: 'info',
  in_progress: 'info',
  risk_accepted: 'warning',
  mitigated: 'success',
  resolved: 'success',
  closed: 'default',
  reopened: 'error',
  false_positive: 'default',
  queued: 'default',
  running: 'info',
  completed: 'success',
  failed: 'error',
  cancelled: 'default',
  partial: 'warning',
  active: 'success',
  inactive: 'default',
  decommissioned: 'warning',
  pending_discovery: 'info',
};
