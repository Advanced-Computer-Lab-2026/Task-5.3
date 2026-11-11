import { randomBytes } from 'node:crypto';
import { doubleCsrf } from 'csrf-csrf';

const fallbackSecret = randomBytes(32).toString('hex');
const secure = process.env.NODE_ENV === 'production';

export const csrfCookieName = secure ? '__Host-csrf' : 'csrf';
export const csrfCookieOptions = {
  httpOnly: true,
  sameSite: 'lax',
  secure,
  path: '/'
};

export const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || fallbackSecret,
  // The authenticated JWT identifies this login, rather than just this user.
  getSessionIdentifier: req => req.cookies.token,
  cookieName: csrfCookieName,
  cookieOptions: csrfCookieOptions,
  getCsrfTokenFromRequest: req => req.get('x-csrf-token')
});

export function csrfToken(req, res) {
  res.set('Cache-Control', 'no-store');
  res.json({ csrfToken: generateCsrfToken(req, res) });
}
