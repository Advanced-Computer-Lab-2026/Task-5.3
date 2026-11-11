import { doubleCsrf } from 'csrf-csrf';

// Anti-CSRF protection using the signed double-submit-cookie pattern.
//
// How it works:
//   1. GET /api/csrf-token generates a token that is HMAC-bound to the caller's
//      session (their auth JWT) and sets it in a cookie; the same token is also
//      returned in the JSON body.
//   2. Our own client reads the token from the body and echoes it back in the
//      `x-csrf-token` header on every state-changing request.
//   3. The server checks that header against the cookie + session. A cross-site
//      attacker's form can make the browser send the cookie, but it can neither
//      READ the token (same-origin policy) nor set a custom header without a
//      CORS preflight we refuse — so the forged request has no valid token.
const {
  generateCsrfToken,
  doubleCsrfProtection,
  invalidCsrfTokenError
} = doubleCsrf({
  // Read lazily so the env var can be set after this module is imported.
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET || 'dev-only-csrf-secret',

  // Tie the token to the logged-in session: a token minted for one user is
  // useless for any other session.
  getSessionIdentifier: (req) => req.cookies?.token || '',

  cookieName: 'csrf-token', // (the default "__Host-" prefix needs HTTPS)
  cookieOptions: {
    sameSite: 'lax',
    secure: false, // true in production (HTTPS only)
    httpOnly: true,
    path: '/'
  },

  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],

  // GET/HEAD/OPTIONS are "safe" methods and stay exempt (default).
  // Login/register run BEFORE a session exists, so there is nothing for an
  // attacker to ride on — they stay exempt as well.
  skipCsrfProtection: (req) =>
    req.path === '/api/auth/login' || req.path === '/api/auth/register',

  errorConfig: { statusCode: 403, message: 'Invalid or missing CSRF token', code: 'EBADCSRFTOKEN' }
});

export { generateCsrfToken, doubleCsrfProtection, invalidCsrfTokenError };
