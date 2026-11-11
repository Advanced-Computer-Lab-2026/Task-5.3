import { doubleCsrf } from 'csrf-csrf';

// Anti-CSRF protection using the double-submit-cookie pattern (csrf-csrf).
//
// GET /api/csrf-token issues a token and sets a matching httpOnly cookie. The
// token is an HMAC of (server secret + the caller's session), so it cannot be
// guessed or forged. The client must echo it back in the `x-csrf-token` header
// on every state-changing request.
//
// A forged cross-site <form> gets the cookies attached automatically, but it
// cannot set a custom header, and CORS stops the attacker's page from reading
// the token response. So the attacker's request has no valid header and gets 403.
const PRE_AUTH_PATHS = new Set(['/api/auth/login', '/api/auth/register']);

const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  // Read the secret lazily so the value from .env (or the tests) is the one used.
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET,
  // Bind each token to the session (the auth JWT cookie). A token issued for one
  // session is useless in another session, including after login or logout.
  getSessionIdentifier: (req) => req.cookies?.token || 'anonymous',
  // No `__Host-` prefix: browsers only accept that prefix on Secure (HTTPS) cookies.
  cookieName: 'x-csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false, // true in production (HTTPS only)
    path: '/'
  },
  // GET/HEAD/OPTIONS are "safe" and are exempt by default (ignoredMethods).
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],
  // Login and register run before a session exists, so they are exempt.
  skipCsrfProtection: (req) => PRE_AUTH_PATHS.has(req.path)
});

export function csrfTokenHandler(req, res) {
  // overwrite: true issues a fresh token for the current session every time.
  const csrfToken = generateCsrfToken(req, res, { overwrite: true });
  res.json({ csrfToken });
}

export { doubleCsrfProtection };
