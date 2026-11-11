
import { doubleCsrf } from 'csrf-csrf';

const {
  generateCsrfToken,
  doubleCsrfProtection
} = doubleCsrf({
  // Use a strong secret stored in the environment.
  // Fall back to JWT_SECRET for environments that haven't
  // configured CSRF_SECRET yet.
  getSecret: () =>
    process.env.CSRF_SECRET || process.env.JWT_SECRET,

  // Bind the CSRF token to the authenticated JWT session.
  // Each login creates a different JWT.
  getSessionIdentifier: (req) =>
    req.cookies?.token || 'anonymous',

  cookieName: 'csrf-token',

  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/'
  },

  // Safe methods do not need CSRF protection.
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],

  // The frontend must send the token in this header.
  getCsrfTokenFromRequest: (req) =>
    req.headers['x-csrf-token'],

  // Login and registration happen before authentication.
  skipCsrfProtection: (req) =>
    req.method === 'POST' &&
    [
      '/api/auth/login',
      '/api/auth/register'
    ].includes(req.path),

  errorConfig: {
    statusCode: 403,
    message: 'Invalid CSRF token'
  }
});

export {
  generateCsrfToken,
  doubleCsrfProtection
};
