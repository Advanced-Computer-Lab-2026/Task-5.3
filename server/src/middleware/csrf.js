import { doubleCsrf } from 'csrf-csrf';

// Anti-CSRF protection using the double-submit-cookie pattern (csrf-csrf).
//
// How it works:
//   1. The client calls GET /api/csrf-token. The server generates a token that is
//      an HMAC of (secret + session identifier + random value), stores it in a
//      cookie, and also returns it in the JSON body.
//   2. On every state-changing request the client echoes the token back in the
//      `x-csrf-token` header. The server checks that the header matches the cookie
//      AND that the HMAC is valid for the current session.
//
// Why the attacker can't pass this check:
//   - The attacker's page can make the browser SEND our cookies, but it cannot
//     READ them or read our API's responses (same-origin policy + CORS), so it
//     never learns the token value.
//   - A plain HTML <form> cannot set custom headers like `x-csrf-token`.
//   - The token is bound to the session (the auth JWT), so a token minted for the
//     attacker's own account is useless against the victim.
const {
  generateCsrfToken,
  doubleCsrfProtection
} = doubleCsrf({
  // Read lazily so the secret can come from .env (or be set by the tests).
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET,

  // Bind each token to the current session. Our session is the JWT in the
  // `token` cookie; before login there is none, so an empty string is used.
  getSessionIdentifier: (req) => req.cookies?.token || '',

  // A plain name: the `__Host-` prefix (the library default) requires HTTPS,
  // which the local http://localhost setup doesn't have.
  cookieName: 'x-csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/'
  },

  // "Safe" methods don't change state, so they are not checked.
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],

  // The client sends the token in this header on every write.
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],

  // Pre-auth routes run before a session exists, so they are exempt.
  skipCsrfProtection: (req) =>
    req.method === 'POST' &&
    ['/api/auth/login', '/api/auth/register'].includes(req.path)
});

// GET /api/csrf-token — hands the client a fresh token for its current session.
// `overwrite: true` always issues a new token, so after login/logout (when the
// session identifier changes) the client gets a token that matches.
export function csrfTokenHandler(req, res) {
  const csrfToken = generateCsrfToken(req, res, { overwrite: true });
  res.json({ csrfToken });
}

export { doubleCsrfProtection };
