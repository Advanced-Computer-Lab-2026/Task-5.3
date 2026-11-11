import { doubleCsrf } from 'csrf-csrf';

const csrf = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET,
  // Each signed-in JWT represents one session. A token from another session
  // cannot be replayed even when the same user has multiple logins.
  getSessionIdentifier: (req) => req.cookies?.token || 'anonymous',
  cookieName: 'csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
  },
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],
});

export const { doubleCsrfProtection, generateCsrfToken, invalidCsrfTokenError } = csrf;
