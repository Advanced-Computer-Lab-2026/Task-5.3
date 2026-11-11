import { doubleCsrf } from 'csrf-csrf';

// Anti-CSRF protection using the double-submit-cookie pattern (csrf-csrf).
//
// 1. The client calls GET /api/csrf-token. The server generates a random token,
//    stores a signed (HMAC) copy in the `csrf_token` cookie and returns the raw
//    token in the JSON body.
// 2. On every state-changing request the client echoes the token in the
//    `x-csrf-token` header (the cookie travels automatically).
// 3. The server recomputes the HMAC and only accepts the request when they match.
//
// A forged cross-site request carries the victim's cookies but can NOT read the
// token and can NOT set a custom header, so it is rejected with 403.

const {
  invalidCsrfTokenError,
  generateCsrfToken,
  doubleCsrfProtection
} = doubleCsrf({
  // Read lazily so the secret is picked up after dotenv loads (and in tests).
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET,

  // Bind each token to the session (the auth cookie).
  getSessionIdentifier: (req) => req.cookies?.token || '',

  // The default "__Host-" cookie name needs HTTPS; we run on http://localhost.
  cookieName: 'csrf_token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/'
  },

  size: 64,
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token']
});

// Pre-auth routes run before a session exists, so they stay exempt.
const EXEMPT_PATHS = new Set(['/api/auth/login', '/api/auth/register']);

export function csrfProtection(req, res, next) {
  if (EXEMPT_PATHS.has(req.path)) return next();
  return doubleCsrfProtection(req, res, next);
}

// GET /api/csrf-token — `overwrite: true` always issues a fresh token, which
// matters right after login/logout when the session identifier changes.
export function csrfTokenHandler(req, res) {
  const csrfToken = generateCsrfToken(req, res, { overwrite: true });
  res.json({ csrfToken });
}

export { invalidCsrfTokenError };