import { doubleCsrf } from 'csrf-csrf';

// Anti-CSRF protection using the double-submit-cookie pattern (csrf-csrf).
//
// How it works:
//  1. The client calls GET /api/csrf-token. The server generates a token that is
//     HMAC-signed with CSRF_SECRET and bound to the current session (the auth
//     cookie). The token is returned in the JSON body, and a hash of it is set in
//     an httpOnly cookie.
//  2. On every state-changing request the client echoes the token back in the
//     `x-csrf-token` header. The server checks that the header token matches the
//     cookie AND was issued for this session.
//
// Why the attacker can't pass this check: an auto-submitting <form> on another
// site can make the browser send our cookies, but it can't set a custom header,
// and CORS stops the attacker's page from reading the token out of the
// /api/csrf-token response. So the forged request arrives without a valid
// token and gets a 403.
const {
  doubleCsrfProtection,
  generateCsrfToken,
  invalidCsrfTokenError
} = doubleCsrf({
  // Read the secret lazily so it can come from .env (or be set by the tests).
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET,
  // Bind each token to the logged-in session. A token issued for one session
  // (or for no session) won't work for another.
  getSessionIdentifier: (req) => req.cookies?.token ?? '',
  // No `__Host-` prefix: browsers only accept those cookies over HTTPS, and this
  // demo runs on plain http://localhost.
  cookieName: 'x-csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false, // true in production (HTTPS only)
    path: '/'
  },
  // GET / HEAD / OPTIONS are "safe" methods and stay exempt.
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  // The client sends the token in a custom header. A plain HTML form can't set
  // a custom header, which is part of what blocks the attack.
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token']
});

// Routes that run before a session exists. There is no session to forge
// requests for yet, so they stay exempt.
const PRE_AUTH_ROUTES = new Set(['/api/auth/login', '/api/auth/register']);

export function csrfProtection(req, res, next) {
  if (PRE_AUTH_ROUTES.has(req.path)) return next();
  return doubleCsrfProtection(req, res, next);
}

// GET /api/csrf-token: issues a token for the current session.
export function csrfTokenHandler(req, res) {
  const csrfToken = generateCsrfToken(req, res, { overwrite: true });
  res.json({ csrfToken });
}

export { invalidCsrfTokenError };
