import { doubleCsrf } from 'csrf-csrf';

// Anti-CSRF using the double-submit-cookie pattern (csrf-csrf).
//
// Why this closes the hole that CORS and SameSite leave open:
//   - The server issues a secret, per-session token. Half of it lives in a
//     dedicated cookie (signed/hashed with CSRF_SECRET), the other half is
//     handed to our own client in the response body of GET /api/csrf-token.
//   - A legitimate request from our app echoes that token back in the
//     `x-csrf-token` header. The server only acts if the header token matches
//     the cookie.
//   - An attacker's page can make the browser *send* the cookie (that is CSRF),
//     but it can neither READ the token (CORS/same-origin policy stop it) nor
//     GUESS it. So it cannot set the matching header, and the write is refused.
//
// `getSecret` is a function so the secret is read lazily, at request time,
// which lets tests set process.env.CSRF_SECRET after this module is imported.
const {
  generateToken,
  doubleCsrfProtection,
  invalidCsrfTokenError,
} = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || 'dev-csrf-secret-change-me',
  // A plain cookie name (no `__Host-` prefix) so the demo works over plain
  // http://localhost. Separate from the auth `token` cookie.
  cookieName: 'csrfToken',
  cookieOptions: {
    httpOnly: true,   // the client reads the token from the JSON body, not this cookie
    sameSite: 'lax',
    secure: false,    // true in production (HTTPS only)
    path: '/',
  },
  size: 64,
  // Safe, non-state-changing methods are never challenged.
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  // Where the echoed token is expected on a state-changing request.
  getTokenFromRequest: (req) => req.headers['x-csrf-token'],
});

export { generateToken, doubleCsrfProtection, invalidCsrfTokenError };
