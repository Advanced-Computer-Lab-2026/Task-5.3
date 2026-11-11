import { doubleCsrf } from 'csrf-csrf';

const isProd = process.env.NODE_ENV === 'production';

// Routes that run before a session exists, so there is no session to bind a token to.
const EXEMPT_PATHS = ['/api/auth/login', '/api/auth/register'];

// Double-submit-cookie CSRF protection.
// - The server issues a random token, HMAC-signed with CSRF_SECRET and bound to the
//   current session (the JWT auth cookie), and stores it in a cookie.
// - Our client must echo the token back in the x-csrf-token header on every write.
// - A forged cross-site request (e.g. an auto-submitting form) can't set a custom
//   header and can't read the token, so it is rejected with 403.
// GET/HEAD/OPTIONS are "safe" methods and are ignored by default.
const { doubleCsrfProtection, generateCsrfToken } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,
  getSessionIdentifier: (req) => req.cookies?.token ?? '',
  // The "__Host-" prefix requires HTTPS, so only use it in production.
  cookieName: isProd ? '__Host-x-csrf-token' : 'x-csrf-token',
  cookieOptions: { sameSite: 'lax', secure: isProd, path: '/', httpOnly: true },
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],
  skipCsrfProtection: (req) => EXEMPT_PATHS.includes(req.path)
});

export { doubleCsrfProtection, generateCsrfToken };
