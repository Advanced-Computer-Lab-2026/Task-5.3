import { randomBytes } from 'node:crypto';
import { doubleCsrf } from 'csrf-csrf';

const fallbackSecret = randomBytes(32).toString('hex');
const production = process.env.NODE_ENV === 'production';

export const { generateCsrfToken, doubleCsrfProtection, invalidCsrfTokenError } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || fallbackSecret,
  // Use the full, verified session JWT, rather than the user's permanent ID.
  getSessionIdentifier: (req) => req.cookies.token,
  cookieName: production ? '__Host-csrf-token' : 'csrf-token',
  cookieOptions: { httpOnly: true, secure: production, sameSite: 'lax', path: '/' },
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token']
});
