/** @type {import('next').NextConfig} */

const deployEnv = process.env.NEXT_PUBLIC_DEPLOY_ENV || 'development';
const apiPort = process.env.NEXT_PUBLIC_API_PORT || '18080';

// Allow browser fetch to the API gateway in sandbox (port 18080) and dev (8080).
const connectSrc =
  deployEnv === 'sandbox' || deployEnv === 'production'
    ? `'self' http://localhost:${apiPort} http://127.0.0.1:${apiPort} https:`
    : `'self' http://localhost:8080 http://127.0.0.1:8080 http://localhost:${apiPort} http://127.0.0.1:${apiPort} https:`;

const securityHeaders = [
  { key: 'X-DNS-Prefetch-Control', value: 'on' },
  { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
  { key: 'X-Frame-Options', value: 'SAMEORIGIN' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
  {
    key: 'Content-Security-Policy',
    value: [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob:",
      "font-src 'self' data:",
      `connect-src ${connectSrc}`,
      "frame-ancestors 'self'",
    ].join('; '),
  },
];

const nextConfig = {
  output: 'standalone',
  reactStrictMode: true,
  poweredByHeader: false,
  async headers() {
    return [{ source: '/(.*)', headers: securityHeaders }];
  },
};

module.exports = nextConfig;
