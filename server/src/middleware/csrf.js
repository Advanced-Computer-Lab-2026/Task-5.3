import { doubleCsrf } from 'csrf-csrf';

// Anti-CSRF protection using the double-submit-cookie pattern (csrf-csrf).
//
// 1. GET /api/csrf-token issues a token. The server stores an HMAC-signed copy
//    in a cookie and returns the token in the JSON body.
// 2. On every state-changing request the client must echo the token in the
//    `x-csrf-token` header. The middleware checks that the header matches the
//    signed cookie AND that it was issued for this session.
//
// Why an attacker can't forge it: their page can make the browser *send* our
// cookies, but it cannot *read* our responses (CORS / same-origin policy), so it
// never learns the token, and an HTML <form> cannot set custom headers anyway.

// Pre-auth routes: no session exists yet, so there is nothing to protect and no
// session to bind a token to. GET/HEAD/OPTIONS are skipped by csrf-csrf itself.
const EXEMPT_PATHS = new Set(['/api/auth/login', '/api/auth/register']);

const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  // Read lazily so the secret can come from .env (or be set by tests at runtime).
  getSecret: () => process.env.CSRF_SECRET,
  // Bind each token to the current session (the JWT cookie). A token issued for
  // one session is useless for another, and logging in/out invalidates it.
  getSessionIdentifier: (req) => req.cookies?.token ?? '',
  // No "__Host-" prefix: that requires `secure`, which plain http://localhost lacks.
  cookieName: 'x-csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/'
  },
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],
  skipCsrfProtection: (req) => EXEMPT_PATHS.has(req.path)
});

// GET /api/csrf-token — hand the client a token for its current session.
export function csrfTokenHandler(req, res) {
  const csrfToken = generateCsrfToken(req, res, { overwrite: true });
  res.json({ csrfToken });
}

// Rejects unsafe requests without a valid token with 403 "invalid csrf token".
export const csrfProtection = doubleCsrfProtection;
