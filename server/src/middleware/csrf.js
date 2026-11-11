import { doubleCsrf } from 'csrf-csrf';

const CSRF_EXEMPT_PATHS = new Set(['/api/auth/login', '/api/auth/register']);

// Double-submit cookie CSRF protection: issues an HMAC-signed httpOnly cookie
// bound to the caller's session cookie and requires a matching x-csrf-token
// header on state-changing requests (pre-auth login/register remain exempt).
export const {
  invalidCsrfTokenError,
  generateCsrfToken,
  validateRequest,
  doubleCsrfProtection
} = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET,
  getSessionIdentifier: (req) => req.cookies?.token || '',
  cookieName: 'csrf-token',
  cookieOptions: {
    sameSite: 'lax',
    path: '/',
    secure: false, // true in production (HTTPS only)
    httpOnly: true
  },
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],
  skipCsrfProtection: (req) => CSRF_EXEMPT_PATHS.has(req.path.replace(/\/+$/, ''))
});
