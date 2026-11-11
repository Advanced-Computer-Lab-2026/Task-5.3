import { doubleCsrf } from 'csrf-csrf';

export const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,
  getSessionIdentifier: (req) => req.cookies.token,
  cookieName: 'csrf-token',
  cookieOptions: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/'
  },
  getCsrfTokenFromRequest: (req) => req.get('x-csrf-token')
});
