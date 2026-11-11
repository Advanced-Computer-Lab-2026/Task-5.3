import { doubleCsrf } from 'csrf-csrf';

const CSRF_COOKIE_NAME = 'csrf-token';

const {
  generateCsrfToken,
  doubleCsrfProtection
} = doubleCsrf({
  getSecret: () => {
    if (!process.env.CSRF_SECRET) {
      throw new Error('CSRF_SECRET is not set');
    }
    return process.env.CSRF_SECRET;
  },
  getSessionIdentifier: (req) => `${req.user.id}:${req.user.jti || ''}`,
  cookieName: CSRF_COOKIE_NAME,
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false,
    path: '/'
  },
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],
  errorConfig: {
    statusCode: 403,
    message: 'Invalid CSRF token',
    code: 'EBADCSRFTOKEN'
  }
});

export function issueCsrfToken(req, res) {
  const csrfToken = generateCsrfToken(req, res);
  res.json({ csrfToken });
}

export { doubleCsrfProtection };

export function csrfErrorHandler(err, req, res, next) {
  if (err?.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ message: 'Invalid CSRF token' });
  }
  return next(err);
}
