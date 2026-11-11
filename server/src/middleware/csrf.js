import { doubleCsrf } from 'csrf-csrf';

// Routes that run BEFORE a session exists. There is no auth cookie to abuse yet,
// so they are exempt (and the client could not have fetched a session-bound
// token for them anyway).
const PRE_AUTH_ROUTES = new Set(['/api/auth/login', '/api/auth/register']);

// Double-submit-cookie CSRF protection (csrf-csrf).
//
// 1. GET /api/csrf-token issues a random token, HMAC-signed with CSRF_SECRET and
//    bound to the current session (the auth cookie). The token goes into an
//    httpOnly cookie AND into the JSON response body.
// 2. The client echoes the token back in the `x-csrf-token` header on every
//    state-changing request.
// 3. `doubleCsrfProtection` checks that the header and the cookie agree and that
//    the signature is valid for this session. If not, it returns 403.
//
// An attacker's page cannot read the token: CORS blocks it from reading our
// responses, and the cookie is httpOnly. A plain HTML <form> cannot set custom
// headers. So a forged request always arrives without a valid header.
const { doubleCsrfProtection, generateCsrfToken } = doubleCsrf({
  // Read env lazily so dotenv/tests can set it after this module loads.
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET,
  // Bind each token to the logged-in session. A token issued for one session
  // is useless for any other session.
  getSessionIdentifier: (req) => req.cookies?.token || '',
  cookieName: 'x-csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production', // HTTPS only in production
    path: '/'
  },
  size: 32,
  // GET/HEAD/OPTIONS are "safe" (they must not change state) and stay exempt.
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  // Read the token from a header only, never from the body. A forged form
  // can put any field in the body, but it cannot add a custom header.
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],
  skipCsrfProtection: (req) => PRE_AUTH_ROUTES.has(req.path)
});

export { doubleCsrfProtection };

// GET /api/csrf-token: hand the client a token for its current session.
export function csrfTokenHandler(req, res) {
  // overwrite: always issue a fresh token tied to the current session (e.g.
  // right after login, when the session identifier has changed).
  const csrfToken = generateCsrfToken(req, res, { overwrite: true });
  res.json({ csrfToken });
}
