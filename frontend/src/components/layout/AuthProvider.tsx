'use client';

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';
import { authApi } from '@/lib/api';
import { mockLogin } from '@/lib/mock-data';
import { isDemoModeEnabled } from '@/lib/env';
import {
  clearStoredAuth,
  getStoredUserRaw,
  MOCK_ACCESS_TOKEN,
  setStoredAuth,
  TOKEN_KEY,
} from '@/lib/auth';
import { LoginRequest, User } from '@/types';

interface AuthContextValue {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (credentials: LoginRequest) => Promise<void>;
  logout: () => Promise<void>;
  hasPermission: (permission: string) => boolean;
  hasAnyPermission: (permissions: string[]) => boolean;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

function parseStoredUser(): User | null {
  const raw = getStoredUserRaw();
  if (!raw) return null;
  try {
    return JSON.parse(raw) as User;
  } catch {
    return null;
  }
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const storedUser = parseStoredUser();
    const token = getStoredToken();
    if (storedUser && token) {
      setUser(storedUser);
      if (token === MOCK_ACCESS_TOKEN && isDemoModeEnabled()) {
        setIsLoading(false);
        return;
      }
      if (token === MOCK_ACCESS_TOKEN) {
        clearStoredAuth();
        setUser(null);
        setIsLoading(false);
        return;
      }
      authApi.me().then(setUser).catch(() => {
        clearStoredAuth();
        setUser(null);
      }).finally(() => setIsLoading(false));
    } else {
      setIsLoading(false);
    }
  }, []);

  const login = useCallback(async (credentials: LoginRequest) => {
    try {
      const response = await authApi.login(credentials);
      setStoredAuth(
        response.access_token,
        response.refresh_token,
        JSON.stringify(response.user)
      );
      setUser(response.user);
    } catch (err) {
      if (!isDemoModeEnabled()) {
        throw err instanceof Error ? err : new Error('Login failed. Please check your credentials.');
      }
      const mock = mockLogin(credentials.username, credentials.password);
      if (!mock) {
        throw new Error('Login failed. Demo mode is enabled — check credentials in your local .env.local.');
      }
      setStoredAuth(mock.access_token, mock.refresh_token, JSON.stringify(mock.user));
      setUser(mock.user);
    }
  }, []);

  const logout = useCallback(async () => {
    try {
      await authApi.logout();
    } catch {
      // ignore logout errors
    }
    clearStoredAuth();
    setUser(null);
  }, []);

  const hasPermission = useCallback(
    (permission: string) => {
      if (!user?.permissions) return false;
      if (user.permissions.includes('*')) return true;
      if (user.permissions.includes(permission)) return true;
      const prefix = permission.split(':')[0];
      return user.permissions.includes(`${prefix}:*`);
    },
    [user]
  );

  const hasAnyPermission = useCallback(
    (permissions: string[]) => permissions.some((p) => hasPermission(p)),
    [hasPermission]
  );

  const value = useMemo(
    () => ({
      user,
      isAuthenticated: !!user,
      isLoading,
      login,
      logout,
      hasPermission,
      hasAnyPermission,
    }),
    [user, isLoading, login, logout, hasPermission, hasAnyPermission]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
}

function getStoredToken(): string | null {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem(TOKEN_KEY);
}

export { getStoredToken };
