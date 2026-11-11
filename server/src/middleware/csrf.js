import { doubleCsrf } from 'csrf-csrf';

// Anti-CSRF protection using the double-submit-cookie pattern (csrf-csrf).
//
// How it works:
//   1. The client calls GET /api/csrf-token. The server returns a token in the
//      JSON body AND sets a matching (httpOnly) cookie that holds an HMAC of it.
//   2. On every state-changing request the client echoes the token back in the
//      `x-csrf-token` header. The server checks header + cookie belong together.
//
// Why the attacker cannot pass this check:
//   - A cross-site <form> cannot set custom headers, so the header is missing.
//   - A cross-site fetch/XHR could set a header, but it cannot READ the token:
//     CORS only lets http://localhost:5175 read our responses.
//   - The token is signed with a server-side secret and bound to the user's
//     session (their auth cookie), so it cannot be guessed or reused across users.
//
// CORS and SameSite alone are not enough: CORS only hides the *response*, it
// does not stop the browser from *sending* a form POST; and SameSite=Lax still
// sends the cookie between localhost:1337 and localhost:4000 (same site — the
// port is not part of a site's identity).
const { doubleCsrfProtection, generateCsrfToken } = doubleCsrf({
  // Read lazily so the secret can come from .env (or be set by the tests).
  getSecret: () => {
    const secret = process.env.CSRF_SECRET;
    if (!secret) throw new Error('CSRF_SECRET is not set');
    return secret;
  },
  // Bind each token to the current session: the JWT auth cookie. A token issued
  // for one user (or before login) is not valid for another session.
  getSessionIdentifier: (req) => req.cookies?.token ?? '',
  // The default "__Host-" cookie requires HTTPS; this demo runs on plain http.
  cookieName: 'x-csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false, // true in production (HTTPS only)
    path: '/'
  },
  // GET/HEAD/OPTIONS are "safe" (no side effects) and stay exempt.
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token']
});

// Pre-auth routes run before a session exists, so there is no session to forge
// a request for. They stay exempt; every other write is protected.
const EXEMPT_PATHS = new Set(['/api/auth/login', '/api/auth/register']);

export function csrfProtection(req, res, next) {
  if (EXEMPT_PATHS.has(req.path)) return next();
  return doubleCsrfProtection(req, res, next);
}

// GET /api/csrf-token — hands the client a token for the current session.
export function csrfTokenHandler(req, res) {
  res.json({ csrfToken: generateCsrfToken(req, res) });
}
