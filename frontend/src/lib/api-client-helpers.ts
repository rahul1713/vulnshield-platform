import { getStoredToken, MOCK_ACCESS_TOKEN } from '@/lib/auth';
import { isDemoModeEnabled } from '@/lib/env';

export function isDemoSession(): boolean {
  return isDemoModeEnabled() && getStoredToken() === MOCK_ACCESS_TOKEN;
}

export function canUseDemoFallback(): boolean {
  return isDemoModeEnabled();
}
