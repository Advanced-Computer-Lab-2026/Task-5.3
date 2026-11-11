import { doubleCsrf } from 'csrf-csrf';

// Double-submit-cookie CSRF protection (csrf-csrf).
//
// GET /api/csrf-token issues a token and sets a matching httpOnly cookie. On every
// state-changing request the client must echo the token in the `x-csrf-token`
// header. The server checks that the header token matches the cookie, was signed
// with CSRF_SECRET, and is bound to the current session.
//
// An attacker's page can make the browser *send* our cookies, but it cannot *read*
// the token (CORS blocks reading the response), and a plain HTML form cannot set
// custom headers. So a forged request has no valid header and gets a 403.
const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  // Read lazily so the secret can come from .env (or be set by the tests).
  getSecret: () => {
    const secret = process.env.CSRF_SECRET;
    if (!secret) throw new Error('CSRF_SECRET is not set');
    return secret;
  },
  // Bind the token to the session (the auth JWT). A token issued for one session
  // is useless for another, and logging in again requires a fresh token.
  getSessionIdentifier: (req) => req.cookies?.token || '',
  cookieName: 'x-csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    secure: process.env.NODE_ENV === 'production'
  },
  // GET/HEAD/OPTIONS are "safe" (they don't change state), so they are exempt.
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token']
});

export { doubleCsrfProtection };

// GET /api/csrf-token
export function csrfTokenHandler(req, res) {
  const csrfToken = generateCsrfToken(req, res, { overwrite: true });
  res.json({ csrfToken });
}
