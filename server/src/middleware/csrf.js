import { doubleCsrf } from 'csrf-csrf';

const csrf = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET,
  // Bind each token to the exact authenticated JWT cookie. A different login
  // receives a different token scope, even for the same account.
  getSessionIdentifier: (req) => req.cookies?.token || '',
  cookieName: 'csrfToken',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/'
  },
  getCsrfTokenFromRequest: (req) => req.get('x-csrf-token')
});

export const generateCsrfToken = csrf.generateCsrfToken;
export const doubleCsrfProtection = csrf.doubleCsrfProtection;
