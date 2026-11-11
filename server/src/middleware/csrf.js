import { doubleCsrf } from 'csrf-csrf';

// Anti-CSRF protection using the double-submit-cookie pattern (csrf-csrf).
//
// How it stops the attack:
//   1. GET /api/csrf-token issues a token and also sets a matching (signed, httpOnly) cookie.
//   2. Every state-changing request must echo that token back in the `x-csrf-token` header.
//   3. The server checks that header against the cookie (and that both were made for THIS session).
//
// An attacker's page can make the browser SEND cookies, but it can never READ our token
// (CORS blocks reading the response) and a plain HTML <form> cannot set custom headers,
// so a forged request arrives without a valid header and is rejected with 403.
const {
  generateCsrfToken,
  doubleCsrfProtection
} = doubleCsrf({
  // Read lazily so the value from .env (or the test setup) is used at request time.
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET,
  // Bind each CSRF token to the logged-in session (the auth cookie). A token issued for one
  // session is useless for another, and pre-login requests share the "anonymous" identity.
  getSessionIdentifier: (req) => req.cookies?.token || 'anonymous',
  cookieName: 'x-csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false, // true in production (HTTPS only)
    path: '/'
  },
  // GET/HEAD/OPTIONS are "safe" (no side effects), so they need no token.
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token']
});

// Pre-auth routes run before a session exists, so there is nothing to forge yet.
const EXEMPT_PATHS = new Set(['/api/auth/login', '/api/auth/register']);

export function csrfProtection(req, res, next) {
  if (EXEMPT_PATHS.has(req.path)) return next();
  return doubleCsrfProtection(req, res, next);
}

// GET /api/csrf-token — hand the client a token for the current session.
export function getCsrfToken(req, res) {
  res.json({ csrfToken: generateCsrfToken(req, res) });
}
