import { doubleCsrf } from 'csrf-csrf';

// Anti-CSRF protection using the signed double-submit-cookie pattern (csrf-csrf).
//
// 1. GET /api/csrf-token issues a token. The server stores an HMAC-signed copy
//    in an httpOnly cookie and returns the token in the JSON body.
// 2. Our client keeps the token in memory and echoes it in the `x-csrf-token`
//    header on every state-changing request (POST/PUT/PATCH/DELETE).
// 3. This middleware checks that the header token matches the cookie, and that
//    both are bound to this session (the auth cookie) and signed with our secret.
//
// Why an attacker's page can't pass this check:
//  - A plain HTML <form> cannot set custom headers, so the header is missing.
//  - The attacker can't read the token: CORS only lets http://localhost:5175
//    read our responses, so the /api/csrf-token body stays hidden from other
//    origins. The browser still *sends* the CSRF cookie, but a cookie alone
//    proves nothing; the matching header is what proves intent.
//  - Tokens are HMAC-signed with CSRF_SECRET and tied to the session, so they
//    can't be guessed, forged, or reused from another account.
const {
  generateCsrfToken,
  doubleCsrfProtection
} = doubleCsrf({
  // Read lazily so tests/env can set it after import. Falls back to the JWT
  // secret so an older .env without CSRF_SECRET doesn't crash the server.
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET,
  // Bind every token to the current login session (the auth cookie). When the
  // user logs in, out, or switches accounts, old tokens stop being valid.
  getSessionIdentifier: (req) => req.cookies?.token || '',
  // Not using the "__Host-" prefix: browsers require it to be Secure, and this
  // dev setup runs over plain http://localhost.
  cookieName: 'x-csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/'
  },
  // Safe, read-only methods are exempt (this is also the library default).
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],
  // Pre-auth routes run before a session exists, so there's nothing to forge
  // a request "as" yet. They issue the session, so they stay exempt.
  skipCsrfProtection: (req) =>
    req.method === 'POST' &&
    ['/api/auth/login', '/api/auth/register'].includes(req.path)
});

// GET /api/csrf-token: issue a token for the current session.
export function csrfTokenHandler(req, res) {
  // overwrite: true always issues a fresh token pair, e.g. right after login,
  // when the session identifier has changed.
  const csrfToken = generateCsrfToken(req, res, { overwrite: true });
  res.json({ csrfToken });
}

export { doubleCsrfProtection };
