import { randomBytes } from 'node:crypto';
import { doubleCsrf } from 'csrf-csrf';

const fallbackSecret = randomBytes(32).toString('hex');
export const csrfCookieName = process.env.NODE_ENV === 'production'
  ? '__Host-csrf-token' : 'csrf-token';

export const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || fallbackSecret,
  getSessionIdentifier: (req) => req.cookies.token,
  cookieName: csrfCookieName,
  cookieOptions: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/'
  },
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token']
});
