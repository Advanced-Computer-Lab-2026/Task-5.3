import { doubleCsrf } from 'csrf-csrf';

const { doubleCsrfProtection, generateCsrfToken } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,
  // Binding the signed token to the JWT cookie makes it specific to this login.
  getSessionIdentifier: (req) => req.cookies?.token || '',
  getTokenFromRequest: (req) => req.headers['x-csrf-token'],
  cookieName: 'csrf-token',
  cookieOptions: { httpOnly: false, sameSite: 'strict', secure: false, path: '/' },
  size: 64
});

export { doubleCsrfProtection, generateCsrfToken };
