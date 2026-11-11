import { doubleCsrf } from 'csrf-csrf';

export const CSRF_COOKIE_NAME = 'csrf-token';

function getCsrfSecret() {
  const secret = process.env.CSRF_SECRET || process.env.JWT_SECRET;
  if (!secret) {
    throw new Error('CSRF_SECRET or JWT_SECRET must be configured');
  }
  return secret;
}

const {
  generateCsrfToken,
  doubleCsrfProtection
} = doubleCsrf({
  getSecret: getCsrfSecret,
  getSessionIdentifier: req => req.cookies.token || req.ip,
  cookieName: CSRF_COOKIE_NAME,
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/'
  },
  errorConfig: {
    statusCode: 403,
    message: 'Invalid CSRF token',
    code: 'EBADCSRFTOKEN'
  }
});

export { generateCsrfToken, doubleCsrfProtection };
