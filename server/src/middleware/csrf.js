import { doubleCsrf } from 'csrf-csrf';

const csrf = doubleCsrf({
  getSecret: () => {
    if (!process.env.CSRF_SECRET) {
      throw new Error('CSRF_SECRET must be configured');
    }
    return process.env.CSRF_SECRET;
  },
  getSessionIdentifier: req => req.cookies.token,
  cookieName: 'csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/'
  }
});

export const generateCsrfToken = csrf.generateCsrfToken;
export const doubleCsrfProtection = csrf.doubleCsrfProtection;
