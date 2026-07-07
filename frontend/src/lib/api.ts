import {
  Asset,
  AuditLog,
  CodeReview,
  ComplianceAssessment,
  DashboardData,
  ListParams,
  LoginRequest,
  LoginResponse,
  PaginatedResponse,
  PatchInfo,
  RedTeamCampaign,
  Report,
  RiskScore,
  Scan,
  ScanType,
  SearchResult,
  User,
  Vulnerability,
  WebScanFinding,
} from '@/types';
import { getStoredToken, MOCK_ACCESS_TOKEN } from '@/lib/auth';
import { isDemoModeEnabled, getApiUrl } from '@/lib/env';
import {
  listParamsToOffset,
  normalizeDashboard,
  normalizePaginated,
  normalizeSearchResults,
} from '@/lib/api-utils';
import { demoStore } from '@/lib/demo-store';

const API_URL = getApiUrl();

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public detail?: unknown
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

/** Demo session: explicit env flag + mock token — never active in sandbox/production builds. */
function isDemoSession(): boolean {
  return isDemoModeEnabled() && getStoredToken() === MOCK_ACCESS_TOKEN;
}

/** Allow read-only mock fallbacks only when demo mode is explicitly enabled (local dev). */
function canUseDemoFallback(): boolean {
  return isDemoModeEnabled();
}

function buildQuery(params?: ListParams): string {
  if (!params) return '';
  const searchParams = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== '') {
      searchParams.set(key, String(value));
    }
  });
  const query = searchParams.toString();
  return query ? `?${query}` : '';
}

async function request<T>(
  endpoint: string,
  options: RequestInit = {},
  authenticated = true
): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  };

  const token = getStoredToken();
  if (authenticated && token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const response = await fetch(`${API_URL}${endpoint}`, {
    ...options,
    headers,
  });

  if (response.status === 401 && authenticated) {
    if (isDemoSession()) {
      throw new ApiError(401, 'API unavailable (demo mode)');
    }
    if (typeof window !== 'undefined') {
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
      localStorage.removeItem('user');
      window.location.href = '/login';
    }
    throw new ApiError(401, 'Unauthorized');
  }

  if (!response.ok) {
    let detail: unknown;
    try {
      detail = await response.json();
    } catch (err) {
      if (!canUseDemoFallback()) throw err;
      detail = await response.text();
    }
    const message =
      typeof detail === 'object' && detail !== null && 'detail' in detail
        ? String((detail as { detail: unknown }).detail)
        : `Request failed with status ${response.status}`;
    throw new ApiError(response.status, message, detail);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return response.json();
}

// ============================================================
// Auth
// ============================================================

export const authApi = {
  login: (credentials: LoginRequest) =>
    request<LoginResponse>(
      '/auth/login',
      { method: 'POST', body: JSON.stringify({ username: credentials.username, password: credentials.password }) },
      false
    ),

  logout: () => request<void>('/auth/logout', { method: 'POST' }),

  me: () => request<User>('/auth/me'),

  refresh: (refreshToken: string) =>
    request<{ access_token: string }>(
      '/auth/refresh',
      { method: 'POST', body: JSON.stringify({ refresh_token: refreshToken }) },
      false
    ),
};

// ============================================================
// Dashboard
// ============================================================

export const dashboardApi = {
  getExecutive: async (): Promise<DashboardData> => {
    try {
      const data = await request<unknown>('/dashboard/executive');
      return normalizeDashboard(data);
    } catch (err) {
      if (!canUseDemoFallback()) throw err;
      const { MOCK_DASHBOARD } = await import('@/lib/mock-data');
      return MOCK_DASHBOARD;
    }
  },
  getSoc: async (): Promise<DashboardData> => {
    try {
      const data = await request<unknown>('/dashboard/soc');
      return normalizeDashboard(data);
    } catch (err) {
      if (!canUseDemoFallback()) throw err;
      const { MOCK_DASHBOARD } = await import('@/lib/mock-data');
      return MOCK_DASHBOARD;
    }
  },
};

// ============================================================
// Assets
// ============================================================

export const assetsApi = {
  list: async (params?: ListParams): Promise<PaginatedResponse<Asset>> => {
    const { limit, offset, page, pageSize } = listParamsToOffset(params);
    try {
      const data = await request<unknown>(`/assets?limit=${limit}&offset=${offset}`);
      return normalizePaginated<Asset>(data, page, pageSize);
    } catch (err) {
      if (!canUseDemoFallback()) throw err;
      const { MOCK_ASSETS, paginate } = await import('@/lib/mock-data');
      const search = params?.search as string | undefined;
      const filtered = search
        ? MOCK_ASSETS.filter((a) => a.name.toLowerCase().includes(search.toLowerCase()))
        : MOCK_ASSETS;
      return paginate(filtered, page, pageSize);
    }
  },
  get: (id: string) => request<Asset>(`/assets/${id}`),
};

// ============================================================
// Vulnerabilities
// ============================================================

export const vulnerabilitiesApi = {
  list: async (params?: ListParams): Promise<PaginatedResponse<Vulnerability>> => {
    const page = params?.page ?? 1;
    const pageSize = params?.page_size ?? 25;
    try {
      const data = await request<unknown>(`/vulnerabilities${buildQuery(params)}`);
      return normalizePaginated<Vulnerability>(data, page, pageSize);
    } catch (err) {
      if (!canUseDemoFallback()) throw err;
      let items = demoStore.getVulnerabilities();
      const search = params?.search as string | undefined;
      if (search) {
        items = items.filter((v) => v.title.toLowerCase().includes(search.toLowerCase()));
      }
      const { paginate } = await import('@/lib/mock-data');
      return paginate(items, page, pageSize);
    }
  },
  get: (id: string) => request<Vulnerability>(`/vulnerabilities/${id}`),
  updateStatus: async (id: string, status: string) => {
    if (isDemoSession()) {
      return demoStore.updateVulnerabilityStatus(id, status as Vulnerability['status']);
    }
    return request(`/vulnerabilities/${id}/status?status=${encodeURIComponent(status)}`, { method: 'PATCH' });
  },
};

// ============================================================
// Scans
// ============================================================

export const scansApi = {
  list: async (params?: ListParams): Promise<PaginatedResponse<Scan>> => {
    const { limit, offset, page, pageSize } = listParamsToOffset(params);
    if (isDemoSession()) {
      const { paginate } = await import('@/lib/mock-data');
      return paginate(demoStore.getScans(), page, pageSize);
    }
    try {
      const data = await request<unknown>(`/scans?limit=${limit}&offset=${offset}`);
      return normalizePaginated<Scan>(data, page, pageSize);
    } catch (err) {
      if (!canUseDemoFallback()) throw err;
      const { paginate } = await import('@/lib/mock-data');
      return paginate(demoStore.getScans(), page, pageSize);
    }
  },
  get: async (id: string): Promise<Scan> => {
    if (isDemoSession()) {
      const scan = demoStore.getScans().find((s) => s.id === id);
      if (!scan) throw new ApiError(404, 'Scan not found');
      return scan;
    }
    return request<Scan>(`/scans/${id}`);
  },
  create: async (payload: { name: string; scan_type: ScanType; target_asset_id?: string; target_config?: Record<string, unknown> }) => {
    if (isDemoSession()) {
      return demoStore.createScan(payload);
    }
    return request<Scan>('/scans', { method: 'POST', body: JSON.stringify(payload) });
  },
  start: async (id: string) => {
    if (isDemoSession()) {
      const scan = demoStore.startScan(id);
      if (!scan) throw new ApiError(404, 'Scan not found');
      return scan;
    }
    return request<Scan>(`/scans/${id}/start`, { method: 'POST' });
  },
  cancel: async (id: string) => {
    if (isDemoSession()) {
      return demoStore.updateScan(id, { status: 'cancelled' });
    }
    return request<Scan>(`/scans/${id}/cancel`, { method: 'POST' });
  },
};

// ============================================================
// Web Scanner
// ============================================================

export const webScannerApi = {
  listFindings: async (params?: ListParams): Promise<PaginatedResponse<WebScanFinding>> => {
    const page = params?.page ?? 1;
    const pageSize = params?.page_size ?? 25;
    try {
      const data = await request<unknown>(`/web-scans${buildQuery(params)}`);
      return normalizePaginated<WebScanFinding>(data, page, pageSize);
    } catch (err) {
      if (!canUseDemoFallback()) throw err;
      const { paginate } = await import('@/lib/mock-data');
      return paginate(demoStore.getWebFindings(), page, pageSize);
    }
  },
  startScan: async (targetUrl: string) => {
    if (isDemoSession()) {
      demoStore.startWebScan(targetUrl);
      return { status: 'completed' };
    }
    return request('/web-scans', {
      method: 'POST',
      body: JSON.stringify({ name: `Web scan ${targetUrl}`, target_url: targetUrl, crawl_depth: 3, active_tests: true }),
    });
  },
};

// ============================================================
// Code Review
// ============================================================

export const codeReviewApi = {
  list: async (params?: ListParams): Promise<PaginatedResponse<CodeReview>> => {
    const { limit, offset, page, pageSize } = listParamsToOffset(params);
    try {
      const data = await request<unknown>(`/reviews?limit=${limit}&offset=${offset}`);
      return normalizePaginated<CodeReview>(data, page, pageSize);
    } catch (err) {
      if (!canUseDemoFallback()) throw err;
      const { paginate } = await import('@/lib/mock-data');
      return paginate(demoStore.getCodeReviews(), page, pageSize);
    }
  },
  create: async (repository_url: string, language: string) => {
    if (isDemoSession()) {
      return demoStore.createCodeReview(repository_url, language);
    }
    return request<CodeReview>('/reviews', {
      method: 'POST',
      body: JSON.stringify({ repository_url, language, branch: 'main', source_code: '// submitted for review' }),
    });
  },
};

// ============================================================
// Red Team
// ============================================================

export const redTeamApi = {
  list: async (params?: ListParams): Promise<PaginatedResponse<RedTeamCampaign>> => {
    const { limit, offset, page, pageSize } = listParamsToOffset(params);
    try {
      const data = await request<unknown>(`/campaigns?limit=${limit}&offset=${offset}`);
      return normalizePaginated<RedTeamCampaign>(data, page, pageSize);
    } catch (err) {
      if (!canUseDemoFallback()) throw err;
      const { paginate } = await import('@/lib/mock-data');
      return paginate(demoStore.getRedTeamCampaigns(), page, pageSize);
    }
  },
  create: async (name: string, description: string) => {
    if (isDemoSession()) {
      return demoStore.createRedTeamCampaign(name, description);
    }
    return request<RedTeamCampaign>('/campaigns', {
      method: 'POST',
      body: JSON.stringify({ name, description, scope: {} }),
    });
  },
};

// ============================================================
// Compliance, Reports, Patch, Risk, Users, Audit, Search
// ============================================================

export const complianceApi = {
  listAssessments: async (params?: ListParams) => {
    const { limit, offset, page, pageSize } = listParamsToOffset(params);
    try {
      const data = await request<unknown>(`/compliance/assessments?limit=${limit}&offset=${offset}`);
      return normalizePaginated<ComplianceAssessment>(data, page, pageSize);
    } catch (err) {
      if (!canUseDemoFallback()) throw err;
      const { MOCK_COMPLIANCE, paginate } = await import('@/lib/mock-data');
      return paginate(MOCK_COMPLIANCE, page, pageSize);
    }
  },
};

export const reportsApi = {
  list: async (params?: ListParams) => {
    const { limit, offset, page, pageSize } = listParamsToOffset(params);
    try {
      const data = await request<unknown>(`/reports?limit=${limit}&offset=${offset}`);
      return normalizePaginated<Report>(data, page, pageSize);
    } catch (err) {
      if (!canUseDemoFallback()) throw err;
      const { MOCK_REPORTS, paginate } = await import('@/lib/mock-data');
      return paginate(MOCK_REPORTS, page, pageSize);
    }
  },
};

export const patchApi = {
  list: async (params?: ListParams) => {
    const { limit, offset, page, pageSize } = listParamsToOffset(params);
    try {
      const data = await request<unknown>(`/patches?limit=${limit}&offset=${offset}`);
      return normalizePaginated<PatchInfo>(data, page, pageSize);
    } catch (err) {
      if (!canUseDemoFallback()) throw err;
      const { MOCK_PATCHES, paginate } = await import('@/lib/mock-data');
      return paginate(MOCK_PATCHES, page, pageSize);
    }
  },
};

export const riskApi = {
  list: async (params?: ListParams) => {
    const { limit, offset, page, pageSize } = listParamsToOffset(params);
    try {
      const data = await request<unknown>(`/risk/scores?limit=${limit}&offset=${offset}`);
      return normalizePaginated<RiskScore>(data, page, pageSize);
    } catch (err) {
      if (!canUseDemoFallback()) throw err;
      const { MOCK_RISK, paginate } = await import('@/lib/mock-data');
      return paginate(MOCK_RISK, page, pageSize);
    }
  },
};

export const usersApi = {
  list: async (params?: ListParams) => {
    const { limit, offset, page, pageSize } = listParamsToOffset(params);
    try {
      const data = await request<unknown>(`/users?limit=${limit}&offset=${offset}`);
      return normalizePaginated<User>(data, page, pageSize);
    } catch (err) {
      if (!canUseDemoFallback()) throw err;
      const { MOCK_USERS, paginate } = await import('@/lib/mock-data');
      return paginate(MOCK_USERS, page, pageSize);
    }
  },
};

export const auditApi = {
  list: async (params?: ListParams) => {
    const { limit, offset, page, pageSize } = listParamsToOffset(params);
    try {
      const data = await request<unknown>(`/audit-logs?limit=${limit}&offset=${offset}`);
      return normalizePaginated<AuditLog>(data, page, pageSize);
    } catch (err) {
      if (!canUseDemoFallback()) throw err;
      const { MOCK_AUDIT_LOGS, paginate } = await import('@/lib/mock-data');
      return paginate(MOCK_AUDIT_LOGS, page, pageSize);
    }
  },
};

export const searchApi = {
  search: async (query: string): Promise<SearchResult[]> => {
    try {
      const data = await request<unknown>(`/search${buildQuery({ q: query, limit: 20 })}`);
      return normalizeSearchResults(data);
    } catch (err) {
      if (!canUseDemoFallback()) throw err;
      const { MOCK_SEARCH } = await import('@/lib/mock-data');
      return MOCK_SEARCH.filter(
        (r) =>
          r.title.toLowerCase().includes(query.toLowerCase()) ||
          r.subtitle?.toLowerCase().includes(query.toLowerCase())
      );
    }
  },
};

export { API_URL };
