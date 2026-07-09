/**
 * Runtime environment configuration.
 * Demo/mock features are OFF by default and must never ship enabled in sandbox/production.
 */

const deployEnv = (): string =>
  process.env.NEXT_PUBLIC_DEPLOY_ENV ?? process.env.NODE_ENV ?? 'development';

export const isDemoModeEnabled = (): boolean => {
  const env = deployEnv();
  if (env === 'production' || env === 'sandbox') {
    return false;
  }
  return process.env.NEXT_PUBLIC_ENABLE_DEMO_MODE === 'true';
};

export const isSandboxOrProduction = (): boolean => {
  const env = deployEnv();
  return env === 'sandbox' || env === 'production';
};

export const isSandboxDeploy = (): boolean => deployEnv() === 'sandbox';

/**
 * API base URL. In sandbox/production browsers, derive from the current hostname
 * so localhost vs 127.0.0.1 never breaks fetch/CORS.
 */
export const getApiUrl = (): string => {
  const configured = process.env.NEXT_PUBLIC_API_URL;
  const apiPort = process.env.NEXT_PUBLIC_API_PORT || '18080';

  if (typeof window !== 'undefined' && isSandboxOrProduction()) {
    return `${window.location.protocol}//${window.location.hostname}:${apiPort}/api/v1`;
  }

  return configured || 'http://localhost:8080/api/v1';
};

/** Default org sandbox login (must match INIT_ADMIN_PASSWORD in .env.sandbox). */
export const ORG_DEFAULT_ADMIN_USERNAME = 'admin';
