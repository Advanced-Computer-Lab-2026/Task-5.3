import { doubleCsrf } from 'csrf-csrf';

export const csrfCookieName = 'csrf-token';
export const { generateCsrfToken, doubleCsrfProtection, invalidCsrfTokenError } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,
  getSessionIdentifier: req => req.cookies.token,
  cookieName: csrfCookieName,
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/'
  },
  getCsrfTokenFromRequest: req => req.get('x-csrf-token')
});
