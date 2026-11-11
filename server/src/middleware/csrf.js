import { doubleCsrf } from 'csrf-csrf';

export const {
  generateCsrfToken,
  doubleCsrfProtection,
} = doubleCsrf({
  getSecret: () => {
    if (!process.env.CSRF_SECRET) {
      throw new Error('CSRF_SECRET is missing');
    }
    return process.env.CSRF_SECRET;
  },

  getSessionIdentifier: (req) => req.cookies.token,

  cookieName: 'csrf-token',

  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
  },

  getCsrfTokenFromRequest: (req) =>
    req.headers['x-csrf-token'],
});