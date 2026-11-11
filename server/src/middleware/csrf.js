import { randomBytes } from 'node:crypto';
import { doubleCsrf } from 'csrf-csrf';

// A random process-local default makes local setup work without another env var.
// Set CSRF_SECRET to a shared random secret when running multiple API processes.
const localSecret = randomBytes(32).toString('hex');
const production = process.env.NODE_ENV === 'production';

export const csrfCookieName = production ? '__Host-csrf-token' : 'csrf-token';
export const csrfCookieOptions = {
  httpOnly: true,
  sameSite: 'lax',
  secure: production,
  path: '/'
};

export const { generateCsrfToken, doubleCsrfProtection, invalidCsrfTokenError } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || localSecret,
  // Authentication must run first; bind tokens to the complete verified JWT.
  getSessionIdentifier: req => req.cookies.token,
  cookieName: csrfCookieName,
  cookieOptions: csrfCookieOptions,
  getCsrfTokenFromRequest: req => req.headers['x-csrf-token']
});
