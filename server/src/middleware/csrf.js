import { doubleCsrf } from 'csrf-csrf';

export const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,
  getSessionIdentifier: (req) => req.cookies?.token || '',
  cookieName: 'x-csrf-token',
  cookieOptions: { httpOnly: true, sameSite: 'lax', secure: false, path: '/' },
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token']
});
