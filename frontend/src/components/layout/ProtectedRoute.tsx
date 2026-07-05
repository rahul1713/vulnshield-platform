'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { Box, CircularProgress } from '@mui/material';
import { useAuth } from '@/components/layout/AuthProvider';

interface ProtectedRouteProps {
  children: React.ReactNode;
  permissions?: string[];
}

export function ProtectedRoute({ children, permissions }: ProtectedRouteProps) {
  const { isAuthenticated, isLoading, hasAnyPermission } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      router.replace('/login');
    }
  }, [isAuthenticated, isLoading, router]);

  useEffect(() => {
    if (!isLoading && isAuthenticated && permissions?.length && !hasAnyPermission(permissions)) {
      router.replace('/dashboard');
    }
  }, [isLoading, isAuthenticated, permissions, hasAnyPermission, router]);

  if (isLoading) {
    return (
      <Box className="flex min-h-screen items-center justify-center bg-surface-dark">
        <CircularProgress color="primary" />
      </Box>
    );
  }

  if (!isAuthenticated) {
    return null;
  }

  if (permissions?.length && !hasAnyPermission(permissions)) {
    return null;
  }

  return <>{children}</>;
}
