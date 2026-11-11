import { doubleCsrf } from 'csrf-csrf';

const EXEMPT = new Set(['/api/auth/login', '/api/auth/register']);

export const {
  generateCsrfToken,
  doubleCsrfProtection
} = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,
  getSessionIdentifier: (req) => req.cookies?.token || '',
  cookieName: 'psifi.x-csrf-token',
  cookieOptions: { sameSite: 'lax', secure: false, httpOnly: true, path: '/' },
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],
  skipCsrfProtection: (req) => EXEMPT.has(req.originalUrl.split('?')[0])
});