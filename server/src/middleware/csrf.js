import { doubleCsrf } from 'csrf-csrf';

export const {
  generateCsrfToken,      // creates the token and sets the CSRF cookie
  doubleCsrfProtection    // middleware that checks the token on writes
} = doubleCsrf({
  // read lazily: the tests set CSRF_SECRET after the app is imported
  getSecret: () => process.env.CSRF_SECRET,
  // tie the token to the logged-in session (the JWT cookie)
  getSessionIdentifier: (req) => req.cookies?.token ?? '',
  cookieName: 'csrf_token',
  cookieOptions: { sameSite: 'lax', secure: false, path: '/' }, // secure: true in production
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token']
});