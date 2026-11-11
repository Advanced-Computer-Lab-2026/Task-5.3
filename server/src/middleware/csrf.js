import { doubleCsrf } from 'csrf-csrf';

// Anti-CSRF protection using the (signed) double-submit-cookie pattern.
//
// 1. A logged-in client asks GET /api/csrf-token. The server returns a random token
//    in the JSON body AND sets a matching httpOnly cookie. The token is an HMAC tied
//    to the user's session (their JWT cookie) using CSRF_SECRET, so it can't be
//    guessed, forged, or reused across sessions.
// 2. On every state-changing request, the client echoes the token back in the
//    `x-csrf-token` header. The server checks header + cookie + session match.
//
// Why the attacker can't pass this check:
//  - Their auto-submitting <form> can't set custom headers.
//  - They can't read the token from /api/csrf-token, because CORS stops their page
//    from reading cross-origin responses.
//  - They can't read the cookie (httpOnly). Cookies aren't isolated by port, so
//    without httpOnly, JavaScript on localhost:1337 could read it.

const isProd = process.env.NODE_ENV === 'production';

// Pre-auth routes: no session exists yet, so there is no CSRF token to check.
const EXEMPT_PATHS = new Set(['/api/auth/login', '/api/auth/register']);

export const CSRF_ERROR_CODE = 'EBADCSRFTOKEN';

export const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  // Read lazily so dotenv (and the tests) can set it after this module loads.
  getSecret: () => {
    const secret = process.env.CSRF_SECRET;
    if (!secret) throw new Error('CSRF_SECRET is not set');
    return secret;
  },
  // Ties each token to the current session. A new login gets a new token.
  getSessionIdentifier: (req) => req.cookies?.token ?? '',
  // The `__Host-` prefix requires `Secure`, which doesn't work over plain http://localhost.
  cookieName: isProd ? '__Host-lf.x-csrf-token' : 'lf.x-csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: isProd,
    path: '/'
  },
  // Only accept the token from a header: a plain HTML form can't send one.
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],
  // GET/HEAD/OPTIONS are "safe" and skipped by default; skip the pre-auth routes too.
  skipCsrfProtection: (req) => EXEMPT_PATHS.has(req.path),
  errorConfig: {
    statusCode: 403,
    message: 'Invalid or missing CSRF token',
    code: CSRF_ERROR_CODE
  }
});
