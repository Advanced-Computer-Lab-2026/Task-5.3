import { createHmac } from 'node:crypto';
import { doubleCsrf } from 'csrf-csrf';

const secure = process.env.NODE_ENV === 'production';
const cookieName = secure ? '__Host-csrf-token' : 'csrf-token';
const cookieOptions = { httpOnly: true, sameSite: 'lax', secure, path: '/' };

const { generateCsrfToken, doubleCsrfProtection, invalidCsrfTokenError } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || createHmac('sha256', process.env.JWT_SECRET)
    .update('campus-lost-found:csrf')
    .digest('hex'),
  // The routes verify the JWT before calling this middleware.
  getSessionIdentifier: (req) => req.cookies.token,
  cookieName,
  cookieOptions
});

export function issueCsrfToken(req, res) {
  res.set('Cache-Control', 'no-store');
  res.json({ csrfToken: generateCsrfToken(req, res) });
}

export function clearCsrfCookie(res) {
  res.clearCookie(cookieName, cookieOptions);
}

export { doubleCsrfProtection, invalidCsrfTokenError };
