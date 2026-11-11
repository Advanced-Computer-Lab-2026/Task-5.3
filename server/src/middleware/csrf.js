import { doubleCsrf } from 'csrf-csrf';

// Double-submit-cookie CSRF protection (csrf-csrf v4).
//
// How it works:
//  1. GET /api/csrf-token returns a random token in the JSON body AND sets a
//     cookie holding an HMAC of that token (signed with CSRF_SECRET and bound
//     to the user's session).
//  2. Every state-changing request must echo the token back in the
//     `x-csrf-token` header. The server checks header and cookie against each other.
//
// Why the attacker can't pass: their page can make the victim's browser SEND
// cookies, but it cannot READ our responses (CORS only lets localhost:5175
// read them), so it never learns the token. And a plain HTML <form> cannot
// set a custom header at all.
const {
  generateCsrfToken,
  doubleCsrfProtection,
} = doubleCsrf({
  // Read lazily so the secret can come from .env or be set by tests at runtime.
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET,

  // Bind each token to the current session (the auth JWT). A token issued
  // for one login session is useless for another one.
  getSessionIdentifier: (req) => req.cookies?.token || '',

  cookieName: 'x-csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false, // true in production (HTTPS only)
    path: '/',
  },

  // Safe methods don't change state, so they don't need a token.
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],

  // Only accept the token from a custom header. Never from the body or the query
  // string: a forged <form> could put it there.
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],
});

// Pre-auth routes run before a session exists, so there's nothing to forge yet
// and no session to bind a token to. They stay exempt.
const EXEMPT_PATHS = new Set(['/api/auth/login', '/api/auth/register']);

export function csrfProtection(req, res, next) {
  if (EXEMPT_PATHS.has(req.path)) return next();
  return doubleCsrfProtection(req, res, next);
}

// GET /api/csrf-token: hand the token to our own client.
export function csrfTokenHandler(req, res) {
  const csrfToken = generateCsrfToken(req, res, { overwrite: true });
  res.json({ csrfToken });
}
