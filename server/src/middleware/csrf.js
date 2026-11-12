import { createHmac } from 'node:crypto';
import { doubleCsrf } from 'csrf-csrf';

// The JWT jti identifies one login session. Deriving an independent key for
// each session means a token from another login cannot be replayed here.
const sessionSecret = (req) => {
  const secret = process.env.CSRF_SECRET || process.env.JWT_SECRET;
  if (!secret) throw new Error('Set CSRF_SECRET (or JWT_SECRET) before starting the server.');
  return createHmac('sha256', secret).update(String(req.user.jti)).digest('hex');
};

const csrf = doubleCsrf({
  getSecret: sessionSecret,
  getSessionIdentifier: (req) => String(req.user.jti),
  cookieName: 'csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
  },
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  getCsrfTokenFromRequest: (req) => req.get('x-csrf-token'),
});

export const csrfProtection = csrf.doubleCsrfProtection;

export function issueCsrfToken(req, res) {
  const csrfToken = csrf.generateCsrfToken(req, res, { overwrite: true });
  res.json({ csrfToken });
}

export function clearCsrfCookie(res) {
  res.clearCookie('csrf-token', {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
  });
}
