import { randomUUID } from 'node:crypto';
import { doubleCsrf } from 'csrf-csrf';

const cookieOptions = {
  httpOnly: true,
  sameSite: 'lax',
  secure: process.env.NODE_ENV === 'production',
  path: '/'
};

export const { generateCsrfToken, doubleCsrfProtection, invalidCsrfTokenError } = doubleCsrf({
  getSecret: () => {
    const secret = process.env.CSRF_SECRET || process.env.JWT_SECRET;
    if (!secret) throw new Error('CSRF_SECRET or JWT_SECRET is required');
    return secret;
  },
  // Bind logged-in tokens to the JWT; use a separate ID before login.
  getSessionIdentifier: (req) => req.cookies.token || req.cookies['csrf-session'] || '',
  cookieName: 'csrf-token',
  cookieOptions,
  // These routes establish a session and must work before a CSRF token exists.
  skipCsrfProtection: (req) => req.method === 'POST' &&
    ['/auth/login', '/auth/register'].includes(req.path),
  getCsrfTokenFromRequest: (req) => req.get('x-csrf-token')
});

export function issueCsrfToken(req, res) {
  if (!req.cookies.token && !req.cookies['csrf-session']) {
    const sessionId = randomUUID();
    req.cookies['csrf-session'] = sessionId;
    res.cookie('csrf-session', sessionId, cookieOptions);
  }
  res.set('Cache-Control', 'no-store');
  res.json({ csrfToken: generateCsrfToken(req, res) });
}
