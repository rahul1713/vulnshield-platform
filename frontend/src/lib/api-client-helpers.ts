import { getStoredToken, MOCK_ACCESS_TOKEN } from '@/lib/auth';
import { isDemoModeEnabled, isSandboxOrProduction } from '@/lib/env';

export function isDemoSession(): boolean {
  if (isSandboxOrProduction()) return false;
  return isDemoModeEnabled() && getStoredToken() === MOCK_ACCESS_TOKEN;
}

export function canUseDemoFallback(): boolean {
  if (isSandboxOrProduction()) return false;
  return isDemoModeEnabled();
}
