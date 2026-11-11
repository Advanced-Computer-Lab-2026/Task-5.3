import { doubleCsrf } from 'csrf-csrf';

// Anti-CSRF protection using the "signed double-submit cookie" pattern (csrf-csrf).
//
// How it works:
//   1. GET /api/csrf-token issues a random token. The server sets a cookie holding
//      an HMAC of (token + session id) signed with CSRF_SECRET, and returns the token
//      in the JSON body.
//   2. Our own client (allowed by CORS to READ that response) keeps the token in
//      memory and echoes it in the `x-csrf-token` header on every write.
//   3. On every state-changing request the server checks that the header token
//      matches the cookie AND the HMAC is valid for the current session.
//
// An attacker's page can make the browser SEND cookies, but it cannot READ the
// token (same-origin policy + CORS), cannot set a custom header on a plain HTML
// form, and cannot forge the HMAC without CSRF_SECRET — so a forged request fails.

const isProd = process.env.NODE_ENV === 'production';

// Routes that must stay exempt: login/register run BEFORE a session exists, so
// there is no session to bind a CSRF token to yet.
const PRE_AUTH_ROUTES = new Set(['/api/auth/login', '/api/auth/register']);

const {
  doubleCsrfProtection,
  generateCsrfToken
} = doubleCsrf({
  // Read lazily so the secret can come from .env / tests at runtime.
  getSecret: () => {
    const secret = process.env.CSRF_SECRET;
    if (!secret) throw new Error('CSRF_SECRET is not set');
    return secret;
  },
  // Bind the token to the logged-in session (the auth JWT cookie). A token
  // issued for one session is useless for another, and a new login (new JWT)
  // invalidates old tokens.
  getSessionIdentifier: (req) => req.cookies?.token || '',
  // "__Host-" prefix requires HTTPS (Secure), so only use it in production.
  cookieName: isProd ? '__Host-csrf' : 'csrf',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: isProd,
    path: '/'
  },
  // "Safe" methods never change state, so they are not checked.
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  // Only accept the token from a header. A cross-site HTML form cannot set custom
  // headers, so we deliberately do NOT read it from the form body.
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],
  skipCsrfProtection: (req) => PRE_AUTH_ROUTES.has(req.path),
  errorConfig: { statusCode: 403, message: 'Invalid or missing CSRF token', code: 'EBADCSRFTOKEN' }
});

// GET /api/csrf-token — hand the client a fresh token (and set its signed cookie).
export function csrfTokenHandler(req, res) {
  const csrfToken = generateCsrfToken(req, res, { overwrite: true });
  res.json({ csrfToken });
}

export { doubleCsrfProtection };
