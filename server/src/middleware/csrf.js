import { doubleCsrf } from 'csrf-csrf';

const {
  doubleCsrfProtection,
  generateCsrfToken
} = doubleCsrf({
  getSecret: () => {
    if (!process.env.CSRF_SECRET) {
      throw new Error('CSRF_SECRET must be configured');
    }
    return process.env.CSRF_SECRET;
  },
  // Bind each signed CSRF token to this login session, not just the user.
  getSessionIdentifier: (req) => req.cookies.token,
  cookieName: 'csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    path: '/'
  },
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS']
});

export { doubleCsrfProtection, generateCsrfToken };
