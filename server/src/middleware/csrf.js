import { doubleCsrf } from 'csrf-csrf';

export const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || 'fallback_secret_key',
  getSessionIdentifier: (req) => req.cookies?.token || '',
  cookieName: 'psifi.x-csrf-token',
  cookieOptions: { sameSite: 'lax', secure: false, httpOnly: true },
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],
  skipCsrfProtection: (req) => ['/api/auth/login', '/api/auth/register'].includes(req.path),
});