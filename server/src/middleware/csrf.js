import { doubleCsrf } from 'csrf-csrf';

// Anti-CSRF protection using the double-submit-cookie pattern (`csrf-csrf`).
//
// How it works:
//   1. The client asks GET /api/csrf-token. We generate a random token, sign it
//      (HMAC with CSRF_SECRET, bound to the caller's session) and send it back
//      twice: in the JSON body AND in an httpOnly cookie.
//   2. On every state-changing request the client must echo the token in the
//      `x-csrf-token` header. The browser sends the cookie on its own.
//   3. We accept the request only if header and cookie match and the signature
//      is valid for this session.
//
// An attacker's page can make the browser send the cookies, but it can neither
// read the token (CORS blocks reading the response of /api/csrf-token) nor add a
// custom header to a plain HTML form — so the forged request is rejected.
const {
  generateCsrfToken,
  doubleCsrfProtection,
  invalidCsrfTokenError
} = doubleCsrf({
  // Read lazily so the value from .env (or the test setup) is picked up.
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET,
  // Tie the token to the logged-in session: a token issued for one session is
  // useless for another one.
  getSessionIdentifier: (req) => req.cookies?.token || '',
  cookieName: 'csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false, // true in production (HTTPS only)
    path: '/'
  },
  // "Safe" methods never change state, so they do not need a token.
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  // The token must arrive in a custom header — never in the body or the query,
  // because a forged HTML form can set those.
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token']
});

// Routes that run before a session exists: there is nothing to forge yet, and
// the client has no session to bind a token to.
const PRE_AUTH_ROUTES = ['/api/auth/login', '/api/auth/register'];

export function csrfProtection(req, res, next) {
  if (PRE_AUTH_ROUTES.includes(req.path)) return next();
  return doubleCsrfProtection(req, res, next);
}

// GET /api/csrf-token
export function sendCsrfToken(req, res) {
  const csrfToken = generateCsrfToken(req, res);
  res.json({ csrfToken });
}

export { invalidCsrfTokenError };
