import { doubleCsrf } from 'csrf-csrf';

const {
  invalidCsrfTokenError,
  generateCsrfToken,
  validateRequest,
  doubleCsrfProtection
} = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || 'fallback-csrf-secret-key-at-least-32-chars-long',
  getSessionIdentifier: (req) => req.cookies?.token || '',
  cookieName: 'x-csrf-token',
  cookieOptions: {
    sameSite: 'lax',
    secure: false, // localhost dev / test
    httpOnly: true
  },
  size: 64,
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token']
});

export {
  invalidCsrfTokenError,
  generateCsrfToken,
  validateRequest,
  doubleCsrfProtection
};
