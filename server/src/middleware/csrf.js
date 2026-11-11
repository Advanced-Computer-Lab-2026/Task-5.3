import { doubleCsrf } from 'csrf-csrf';

// Anti-CSRF protection using the double-submit-cookie pattern (csrf-csrf).
//
// GET /api/csrf-token gives the client two things:
//   1. a token in the JSON body, which our own client reads and sends back
//      in the `x-csrf-token` header on every write, and
//   2. an httpOnly cookie holding an HMAC of that token. The HMAC is signed with
//      CSRF_SECRET and bound to the current session (the auth cookie).
//
// When a write comes in, the server checks that the header token matches the
// cookie's HMAC. An attacker's page can make the browser *send* cookies, but it
// cannot *read* the token: CORS blocks it from reading responses from our API,
// and a forged HTML form cannot set custom headers. So a forged request has no
// valid header and gets 403.
const { doubleCsrfProtection, generateCsrfToken } = doubleCsrf({
  // Read the secret lazily so it is picked up after dotenv (and in tests).
  getSecret: () => process.env.CSRF_SECRET,
  // Bind the token to the logged-in session. A token issued for one session
  // (or before login) is useless for another.
  getSessionIdentifier: (req) => req.cookies?.token || '',
  // The default "__Host-" name requires Secure (HTTPS). We use plain http in dev.
  cookieName: 'x-csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/'
  },
  // GET/HEAD/OPTIONS are "safe" methods and are ignored by default.
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token']
});

// Pre-auth routes: no session exists yet, so there is nothing to forge on behalf of.
// Full paths, checked against req.baseUrl + req.path (req.path alone is relative
// to the mount point, e.g. "/auth/login" under app.use('/api', ...)).
const EXEMPT_PATHS = new Set(['/api/auth/register', '/api/auth/login']);

export function csrfProtection(req, res, next) {
  if (EXEMPT_PATHS.has(req.baseUrl + req.path)) return next();
  return doubleCsrfProtection(req, res, next);
}

// GET /api/csrf-token. Always issue a fresh token so it matches the current session.
export function csrfTokenHandler(req, res) {
  const csrfToken = generateCsrfToken(req, res, { overwrite: true });
  res.json({ csrfToken });
}
