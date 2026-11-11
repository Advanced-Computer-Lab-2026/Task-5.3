import { doubleCsrf } from 'csrf-csrf';

// Anti-CSRF protection using the double-submit-cookie pattern (csrf-csrf).
//
// How it defeats the attack:
//   1. GET /api/csrf-token returns a token in the JSON body AND sets the same
//      value in an httpOnly cookie. The token is an HMAC (keyed by CSRF_SECRET)
//      over the caller's session identifier + a random value, so it cannot be
//      guessed or forged, and it is bound to the current session.
//   2. Every state-changing request must echo the token back in the
//      `x-csrf-token` header. The server checks header === cookie AND that the
//      HMAC is valid for this session.
//   3. An attacker's page can make the browser SEND cookies, but it cannot READ
//      the token (CORS blocks reading our responses, the cookie is httpOnly) and
//      a plain HTML <form> cannot set custom headers — so a forged request
//      arrives without a valid header and is rejected with 403.

// Routes that run before a session exists (no auth cookie to ride on) are exempt.
const PRE_AUTH_ROUTES = new Set(['/api/auth/login', '/api/auth/register']);

const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  // Read lazily so the secret can come from .env (or be set by tests at runtime).
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET,
  // Bind each CSRF token to the current session (the auth JWT cookie). A token
  // issued for one session is useless for another, and a new login invalidates it.
  getSessionIdentifier: (req) => req.cookies?.token ?? '',
  // No `__Host-` prefix: browsers only accept those on HTTPS, and dev runs on http.
  cookieName: 'psifi.x-csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'strict',
    path: '/',
    secure: process.env.NODE_ENV === 'production'
  },
  // "Safe" methods never change state, so they are not checked.
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],
  skipCsrfProtection: (req) => PRE_AUTH_ROUTES.has(req.path)
});

// GET /api/csrf-token — hand the client a token for its current session.
export function csrfTokenHandler(req, res) {
  const csrfToken = generateCsrfToken(req, res);
  res.json({ csrfToken });
}

export { doubleCsrfProtection };
