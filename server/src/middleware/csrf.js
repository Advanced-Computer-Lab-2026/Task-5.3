
import { doubleCsrf } from 'csrf-csrf';

const {
  doubleCsrfProtection,
  generateCsrfToken,
} = doubleCsrf({
  getSecret: () => {
    if (!process.env.CSRF_SECRET) {
      throw new Error('CSRF_SECRET is missing from environment variables');
    }

    return process.env.CSRF_SECRET;
  },

  getSessionIdentifier: (req) =>
    req.cookies?.token || 'anonymous',

  cookieName: 'csrf-token',

  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
  },

  getCsrfTokenFromRequest: (req) =>
    req.headers['x-csrf-token'],

  skipCsrfProtection: (req) =>
    req.path === '/api/auth/login' ||
    req.path === '/api/auth/register',
});

export function csrfTokenHandler(req, res, next) {
  try {
    const csrfToken = generateCsrfToken(req, res);

    return res.json({ csrfToken });
  } catch (error) {
    next(error);
  }
}

export const csrfProtection = doubleCsrfProtection;
