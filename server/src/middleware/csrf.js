import { doubleCsrf } from 'csrf-csrf';

// Anti-CSRF protection using the signed double-submit-cookie pattern.
//
// 1. GET /api/csrf-token hands the client a token AND sets a matching httpOnly
//    cookie. The token is an HMAC bound to the user's session (their auth cookie)
//    and signed with CSRF_SECRET, so it cannot be guessed or forged.
// 2. Every state-changing request (POST/PUT/PATCH/DELETE) must echo the token
//    back in the `x-csrf-token` header. The server checks that the header, the
//    cookie and the current session all match.
//
// An attacker's page can make the browser *send* our cookies, but it cannot
// *read* the token (same-origin policy + CORS block reading our responses) and
// a plain HTML <form> cannot set a custom header. So the forged request arrives
// without a valid token and is rejected with 403.

// Pre-auth routes run before a session exists, so there is nothing to bind a
// token to yet. They stay exempt.
const EXEMPT_PATHS = new Set(['/api/auth/login', '/api/auth/register']);

const {
  generateCsrfToken,
  doubleCsrfProtection
} = doubleCsrf({
  // Read lazily so the secret can come from .env (or be set by tests at runtime).
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET,
  // Tie each token to the current session: a token issued for one login is
  // useless for another session.
  getSessionIdentifier: (req) => req.cookies?.token || '',
  cookieName: 'x-csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/'
  },
  // "Safe" methods never change state, so they do not need a token.
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],
  skipCsrfProtection: (req) => EXEMPT_PATHS.has(req.path)
});

// GET /api/csrf-token: issue a token for the current session.
export function csrfTokenHandler(req, res) {
  // overwrite: always mint a fresh token, e.g. after the session changed on login.
  const csrfToken = generateCsrfToken(req, res, { overwrite: true });
  res.json({ csrfToken });
}

export { doubleCsrfProtection };
