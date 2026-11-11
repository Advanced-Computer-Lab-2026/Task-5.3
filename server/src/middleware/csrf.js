import { doubleCsrf } from 'csrf-csrf';

// Anti-CSRF protection using the double-submit-cookie pattern (csrf-csrf).
//
// How it defeats the attack:
//   1. GET /api/csrf-token issues a token. The server also sets a companion
//      httpOnly cookie holding an HMAC of that token, signed with CSRF_SECRET and
//      bound to the current session (the auth cookie).
//   2. Our client reads the token from the JSON response and echoes it back in
//      the `x-csrf-token` header on every state-changing request.
//   3. The server checks that the header token matches the cookie's HMAC for
//      this session. A forged cross-site request (e.g. an auto-submitting HTML
//      form) still gets the cookies attached by the browser, but it CANNOT set a
//      custom header, and it cannot read the token (the same-origin policy / CORS
//      stop the attacker page from reading our responses). So it fails with 403.
const {
  doubleCsrfProtection,
  generateCsrfToken,
  invalidCsrfTokenError
} = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,
  // Bind each token to the current session so a token issued for one session
  // (or for a logged-out visitor) is useless for another.
  getSessionIdentifier: (req) => req.cookies?.token || 'anonymous',
  cookieName: 'x-csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/'
  },
  // Only accept the token from a custom header — never from the body/query,
  // which a plain HTML form could populate.
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],
  // "Safe" methods never change state, so they are exempt.
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS']
});

// Pre-auth routes run before a session exists, so there is nothing to forge yet.
// They stay exempt (the client also has no session-bound token to send there).
const EXEMPT_PATHS = new Set(['/api/auth/login', '/api/auth/register']);

export function csrfProtection(req, res, next) {
  if (EXEMPT_PATHS.has(req.path)) return next();
  return doubleCsrfProtection(req, res, next);
}

// GET /api/csrf-token — hand the client a fresh token for its current session.
export function csrfTokenHandler(req, res) {
  const csrfToken = generateCsrfToken(req, res, { overwrite: true });
  res.json({ csrfToken });
}

// Turn csrf-csrf's error into a clean 403 response.
export function csrfErrorHandler(err, req, res, next) {
  if (err === invalidCsrfTokenError || err?.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ message: 'Invalid or missing CSRF token' });
  }
  return next(err);
}
