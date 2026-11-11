import { doubleCsrf } from 'csrf-csrf';

// Anti-CSRF protection using the double-submit-cookie pattern (csrf-csrf).
//
// 1. The client calls GET /api/csrf-token. The server generates a token that is
//    an HMAC of (secret + the caller's session), stores it in a cookie AND
//    returns it in the JSON body.
// 2. On every state-changing request the client echoes that token back in the
//    `x-csrf-token` header. The middleware checks that header === cookie and
//    that the HMAC is valid for this session.
//
// A cross-site attacker's page can make the browser *send* our cookies, but it
// can neither *read* the token (CORS blocks reading the response) nor set a
// custom header on a plain HTML form — so a forged request fails with 403.
// CORS and SameSite alone are not enough: CORS only stops reading the response,
// and SameSite keys off the site (localhost:1337 and localhost:4000 are the
// same site), so the auth cookie still rides along.

const isProd = process.env.NODE_ENV === 'production';

// Routes that run before a session exists. There is no session to ride on, so
// there is nothing to forge yet; the client also cannot have a session-bound
// token before logging in.
const PRE_AUTH_PATHS = new Set(['/api/auth/login', '/api/auth/register']);

const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  // Read lazily so tests / dotenv can set the env var after this module loads.
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET,
  // Bind each token to the logged-in session (the auth cookie), so a token
  // issued to one session is useless for another.
  getSessionIdentifier: (req) => req.cookies?.token || '',
  // `__Host-` prefixed cookies require HTTPS, so only use it in production.
  cookieName: isProd ? '__Host-x-csrf-token' : 'x-csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: isProd,
    path: '/'
  },
  // GET/HEAD/OPTIONS are "safe" (must not change state) and stay exempt.
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],
  skipCsrfProtection: (req) => PRE_AUTH_PATHS.has(req.path)
});

// GET /api/csrf-token — issue a token for the current session.
export function csrfTokenHandler(req, res) {
  // overwrite: true -> always mint a token for the *current* session (e.g. right
  // after login, when the session identifier just changed).
  const csrfToken = generateCsrfToken(req, res, { overwrite: true });
  res.json({ csrfToken });
}

export { doubleCsrfProtection };
