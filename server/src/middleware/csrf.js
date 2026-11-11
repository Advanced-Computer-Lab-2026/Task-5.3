import { createHmac } from 'node:crypto';
import { doubleCsrf } from 'csrf-csrf';

const secure = process.env.NODE_ENV === 'production';
const cookieName = secure ? '__Host-csrf-token' : 'csrf-token';
const cookieOptions = { httpOnly: true, sameSite: 'lax', secure, path: '/' };

const { generateCsrfToken, doubleCsrfProtection, invalidCsrfTokenError } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || createHmac('sha256', process.env.JWT_SECRET)
    .update('campus-lost-and-found:csrf')
    .digest('hex'),
  getSessionIdentifier: req => req.cookies.token,
  getTokenFromRequest: req => req.get('x-csrf-token'),
  cookieName,
  cookieOptions
});

export function issueCsrfToken(req, res) {
  res.set('Cache-Control', 'no-store').json({ csrfToken: generateCsrfToken(req, res) });
}

export function requireCsrf(req, res, next) {
  doubleCsrfProtection(req, res, err => {
    if (err === invalidCsrfTokenError) {
      return res.status(403).json({ message: 'Invalid CSRF token' });
    }
    return next(err);
  });
}

export function clearCsrfCookie(res) {
  res.clearCookie(cookieName, cookieOptions);
}
