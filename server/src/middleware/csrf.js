import { doubleCsrf } from 'csrf-csrf';

export const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET,
  // bind the token to the logged-in session so one user's token is useless for another
  getSessionIdentifier: (req) => req.cookies?.token || '',
  cookieName: 'csrf-token',
  cookieOptions: { httpOnly: true, sameSite: 'lax', secure: false, path: '/' },
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token']
});