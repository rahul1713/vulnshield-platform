/**
 * Runtime environment configuration.
 * Demo/mock features are OFF by default and must never ship enabled in sandbox/production.
 */

export const isDemoModeEnabled = (): boolean => {
  const deployEnv = process.env.NEXT_PUBLIC_DEPLOY_ENV ?? process.env.NODE_ENV;
  if (deployEnv === 'production' || deployEnv === 'sandbox') {
    return false;
  }
  return process.env.NEXT_PUBLIC_ENABLE_DEMO_MODE === 'true';
};

export const isSandboxOrProduction = (): boolean => {
  const env = process.env.NEXT_PUBLIC_DEPLOY_ENV ?? process.env.NODE_ENV;
  return env === 'sandbox' || env === 'production';
};

export const isSandboxDeploy = (): boolean =>
  (process.env.NEXT_PUBLIC_DEPLOY_ENV ?? process.env.NODE_ENV) === 'sandbox';

export const getApiUrl = (): string =>
  process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080/api/v1';
