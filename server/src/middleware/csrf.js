import { doubleCsrf } from 'csrf-csrf';

// Anti-CSRF protection using the double-submit-cookie pattern (csrf-csrf).
//
// How it works:
//   1. The client calls GET /api/csrf-token. The server generates a token that is
//      HMAC-signed with a server secret AND bound to the user's session (the auth
//      cookie), sets it in a cookie, and returns it in the JSON body.
//   2. On every state-changing request the client echoes the token in the
//      `x-csrf-token` header. The server checks header === cookie and that the
//      HMAC is valid for this session.
//
// Why the attacker can't pass: a cross-site page cannot read our cookies or our
// API responses (Same-Origin Policy), so it can't learn the token, and a plain
// auto-submitting <form> can't set custom headers at all. The forged request
// arrives with the auth cookie but no valid header, so it gets a 403.
//
// Why CORS/SameSite alone aren't enough: CORS only stops the attacker *reading*
// responses. A simple form POST is still sent and executed. SameSite keys off the
// site (registrable domain), not the origin, so localhost:1337 -> localhost:4000
// (or any sibling subdomain) still counts as same-site and gets the cookie.

// Pre-auth routes: no session exists yet, so there is nothing to forge on behalf of.
const EXEMPT_PATHS = new Set(['/api/auth/login', '/api/auth/register']);

const { doubleCsrfProtection, generateCsrfToken } = doubleCsrf({
  // Read lazily so the secret can come from .env (or be set by tests at runtime).
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET,
  // Bind the token to the current session, so a token from one session (or one
  // the attacker obtained for their own account) is useless for another.
  getSessionIdentifier: (req) => req.cookies?.token ?? '',
  // The default "__Host-" prefixed name requires Secure (HTTPS); we run on http locally.
  cookieName: 'x-csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/'
  },
  // "Safe" methods don't change state, so they are not checked.
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  // Only accept the token from a header. Never from the body: a form can set body fields.
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],
  skipCsrfProtection: (req) => EXEMPT_PATHS.has(req.path)
});

// Wraps the library middleware so any CSRF failure becomes a clean 403 JSON response.
export function csrfProtection(req, res, next) {
  doubleCsrfProtection(req, res, (err) => {
    if (err) return res.status(403).json({ message: 'Invalid or missing CSRF token' });
    next();
  });
}

// GET /api/csrf-token: hands the client a token for its current session.
export function csrfTokenHandler(req, res) {
  const csrfToken = generateCsrfToken(req, res, { overwrite: true });
  res.json({ csrfToken });
}
