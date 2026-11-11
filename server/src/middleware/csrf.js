import { doubleCsrf } from 'csrf-csrf';

export const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,
  getSessionIdentifier: req => req.cookies.token ?? '',
  cookieName: 'campus-csrf',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false,
    path: '/',
  },
  getCsrfTokenFromRequest: req => req.get('x-csrf-token'),
  skipCsrfProtection: req =>
    req.method === 'POST' &&
    /^\/api\/auth\/(?:login|register)\/?$/i.test(req.path),
});
