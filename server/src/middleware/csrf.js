import { doubleCsrf } from 'csrf-csrf';

const isProd = process.env.NODE_ENV === 'production';

// Pre-auth routes: no session exists yet, so there is nothing to forge.
const CSRF_EXEMPT = new Set(['/api/auth/login', '/api/auth/register']);

export const {
  generateCsrfToken,
  doubleCsrfProtection,
  invalidCsrfTokenError,
} = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,
  // Ties each CSRF token to the logged-in session (the JWT cookie)
  getSessionIdentifier: (req) => req.cookies.token || '',
  // "__Host-" cookies need HTTPS, so only use that prefix in production
  cookieName: isProd ? '__Host-psifi.x-csrf-token' : 'x-csrf-token',
  cookieOptions: { httpOnly: true, sameSite: 'strict', secure: isProd, path: '/' },
  // Header only: a cross-site <form> can't set custom headers
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],
  skipCsrfProtection: (req) => CSRF_EXEMPT.has(req.path),
});