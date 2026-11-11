import { doubleCsrf } from 'csrf-csrf';

// Anti-CSRF protection using the double-submit-cookie pattern (csrf-csrf).
//
// 1. GET /api/csrf-token hands the client a token AND sets a matching signed cookie.
// 2. On every state-changing request the client echoes the token in the
//    `x-csrf-token` header. The middleware checks that the header matches the
//    cookie and that both are HMAC-bound to this session (the auth JWT).
//
// An attacker's page can make the browser *send* our cookies, but it can neither
// read the token (CORS blocks reading the response) nor set a custom header on a
// cross-site form POST, so a forged request fails with 403.

// Pre-auth routes run before a session exists, so they cannot carry a
// session-bound token yet. Everything else that mutates state is protected.
const EXEMPT_PATHS = new Set(['/api/auth/login', '/api/auth/register']);

const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  // Read lazily so the secret can come from the environment at runtime.
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET,
  // Bind the token to the current session: a token issued for one login is
  // useless for another session.
  getSessionIdentifier: (req) => req.cookies?.token || '',
  cookieName: 'x-csrf-token', // use the "__Host-" prefix in production (requires HTTPS)
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false, // true in production (HTTPS only)
    path: '/'
  },
  // GET/HEAD/OPTIONS are "safe" and are ignored by default.
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],
  skipCsrfProtection: (req) => EXEMPT_PATHS.has(req.path)
});

export { doubleCsrfProtection };

// GET /api/csrf-token
export function csrfTokenHandler(req, res) {
  const csrfToken = generateCsrfToken(req, res, { overwrite: true });
  res.json({ csrfToken });
}
