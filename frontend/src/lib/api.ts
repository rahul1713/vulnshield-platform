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
  SearchResult,
  User,
  Vulnerability,
  WebScanFinding,
} from '@/types';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080/api/v1';

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

import { getStoredToken } from '@/lib/auth';

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

  if (authenticated) {
    const token = getStoredToken();
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
  }

  const response = await fetch(`${API_URL}${endpoint}`, {
    ...options,
    headers,
  });

  if (response.status === 401 && authenticated) {
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
    } catch {
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
    request<LoginResponse>('/auth/login', {
      method: 'POST',
      body: JSON.stringify(credentials),
    }, false),

  logout: () =>
    request<void>('/auth/logout', { method: 'POST' }),

  me: () => request<User>('/auth/me'),

  refresh: (refreshToken: string) =>
    request<{ access_token: string }>('/auth/refresh', {
      method: 'POST',
      body: JSON.stringify({ refresh_token: refreshToken }),
    }, false),
};

// ============================================================
// Dashboard
// ============================================================

export const dashboardApi = {
  getExecutive: () => request<DashboardData>('/dashboard/executive'),
  getSoc: () => request<DashboardData>('/dashboard/soc'),
};

// ============================================================
// Assets
// ============================================================

export const assetsApi = {
  list: (params?: ListParams) =>
    request<PaginatedResponse<Asset>>(`/assets${buildQuery(params)}`),
  get: (id: string) => request<Asset>(`/assets/${id}`),
};

// ============================================================
// Vulnerabilities
// ============================================================

export const vulnerabilitiesApi = {
  list: (params?: ListParams) =>
    request<PaginatedResponse<Vulnerability>>(`/vulnerabilities${buildQuery(params)}`),
  get: (id: string) => request<Vulnerability>(`/vulnerabilities/${id}`),
};

// ============================================================
// Scans
// ============================================================

export const scansApi = {
  list: (params?: ListParams) =>
    request<PaginatedResponse<Scan>>(`/scans${buildQuery(params)}`),
  get: (id: string) => request<Scan>(`/scans/${id}`),
};

// ============================================================
// Web Scanner
// ============================================================

export const webScannerApi = {
  listFindings: (params?: ListParams) =>
    request<PaginatedResponse<WebScanFinding>>(`/web-scanner/findings${buildQuery(params)}`),
  listScans: (params?: ListParams) =>
    request<PaginatedResponse<Scan>>(`/web-scanner/scans${buildQuery(params)}`),
};

// ============================================================
// Code Review
// ============================================================

export const codeReviewApi = {
  list: (params?: ListParams) =>
    request<PaginatedResponse<CodeReview>>(`/code-review${buildQuery(params)}`),
};

// ============================================================
// Red Team
// ============================================================

export const redTeamApi = {
  list: (params?: ListParams) =>
    request<PaginatedResponse<RedTeamCampaign>>(`/red-team/campaigns${buildQuery(params)}`),
};

// ============================================================
// Compliance
// ============================================================

export const complianceApi = {
  listAssessments: (params?: ListParams) =>
    request<PaginatedResponse<ComplianceAssessment>>(`/compliance/assessments${buildQuery(params)}`),
};

// ============================================================
// Reports
// ============================================================

export const reportsApi = {
  list: (params?: ListParams) =>
    request<PaginatedResponse<Report>>(`/reports${buildQuery(params)}`),
};

// ============================================================
// Patch Intelligence
// ============================================================

export const patchApi = {
  list: (params?: ListParams) =>
    request<PaginatedResponse<PatchInfo>>(`/patch-intelligence${buildQuery(params)}`),
};

// ============================================================
// Risk
// ============================================================

export const riskApi = {
  list: (params?: ListParams) =>
    request<PaginatedResponse<RiskScore>>(`/risk/scores${buildQuery(params)}`),
};

// ============================================================
// Users & Audit
// ============================================================

export const usersApi = {
  list: (params?: ListParams) =>
    request<PaginatedResponse<User>>(`/users${buildQuery(params)}`),
};

export const auditApi = {
  list: (params?: ListParams) =>
    request<PaginatedResponse<AuditLog>>(`/audit-logs${buildQuery(params)}`),
};

// ============================================================
// Global Search
// ============================================================

export const searchApi = {
  search: (query: string) =>
    request<SearchResult[]>(`/search${buildQuery({ q: query, limit: 20 })}`),
};

export { API_URL };
