import { doubleCsrf } from 'csrf-csrf';

// Anti-CSRF protection using the double-submit-cookie pattern (csrf-csrf).
//
// 1. GET /api/csrf-token gives the client a random token and also stores a
//    signed copy of it in an httpOnly cookie.
// 2. On every state-changing request (POST/PUT/PATCH/DELETE) the client must
//    send the token back in the `x-csrf-token` header.
// 3. The server checks that the header matches the cookie, that the HMAC
//    (signed with CSRF_SECRET) is valid, and that the token belongs to the
//    current session (the auth cookie). Otherwise it answers 403.
//
// An attacker's page cannot read our cookies or our responses (same-origin
// policy), and a plain HTML <form> cannot set custom headers, so a forged
// request never carries a valid token.
const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET,
  // Bind each token to the logged-in session, so a token issued for one
  // session cannot be replayed with another.
  getSessionIdentifier: (req) => req.cookies?.token || '',
  cookieName: 'csrf_token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    secure: process.env.NODE_ENV === 'production'
  },
  // GET, HEAD and OPTIONS are "safe" and are not checked (the library default).
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token']
});

// Pre-auth routes run before a session exists, so there is nothing to bind a
// token to yet. They stay exempt.
const CSRF_EXEMPT = new Set(['/api/auth/login', '/api/auth/register']);

export function csrfProtection(req, res, next) {
  if (CSRF_EXEMPT.has(req.path)) return next();
  return doubleCsrfProtection(req, res, next);
}

// GET /api/csrf-token: hand the client a fresh token for its current session.
export function csrfTokenHandler(req, res) {
  const csrfToken = generateCsrfToken(req, res, { overwrite: true });
  res.json({ csrfToken });
}
