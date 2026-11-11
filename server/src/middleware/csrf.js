import { doubleCsrf } from 'csrf-csrf';

const secure = process.env.NODE_ENV === 'production';
export const csrfCookieName = secure ? '__Host-csrf-token' : 'csrf-token';
export const csrfCookieOptions = { httpOnly: true, sameSite: 'lax', path: '/', secure };

export const { generateCsrfToken, doubleCsrfProtection, invalidCsrfTokenError } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET,
  // The JWT has already been verified by requireAuth.
  getSessionIdentifier: (req) => req.user.jti || req.cookies.token,
  cookieName: csrfCookieName,
  cookieOptions: csrfCookieOptions,
  getCsrfTokenFromRequest: (req) => req.get('x-csrf-token')
});
