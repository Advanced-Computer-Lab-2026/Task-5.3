
import { doubleCsrf } from 'csrf-csrf';

const {
  generateCsrfToken,
  doubleCsrfProtection
} = doubleCsrf({
  getSecret: () => {
    const secret = process.env.CSRF_SECRET;

    if (!secret) {
      throw new Error('CSRF_SECRET is required');
    }

    return secret;
  },

  // Bind the CSRF token to the logged-in session.
  getSessionIdentifier: (req) => {
    return req.cookies?.token || '';
  },

  cookieName: 'csrf-token',

  cookieOptions: {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    path: '/'
  },

  getCsrfTokenFromRequest: (req) => {
    return req.headers['x-csrf-token'];
  }
});

export { generateCsrfToken };

export function csrfProtection(req, res, next) {
  // Login and registration are pre-authentication routes.
  if (
    req.method === 'POST' &&
    (
      req.path === '/api/auth/login' ||
      req.path === '/api/auth/register'
    )
  ) {
    return next();
  }

  return doubleCsrfProtection(req, res, next);
}
