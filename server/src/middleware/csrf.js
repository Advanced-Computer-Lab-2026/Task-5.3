import { doubleCsrf } from 'csrf-csrf';

// Double-submit-cookie CSRF protection.
// The server sets a signed CSRF cookie AND hands the client the matching token in
// a JSON body. The client must echo that token in the `x-csrf-token` header.
// A cross-site attacker page cannot read our responses or set custom headers on a
// form post, so a forged request arrives without the header and gets 403.
const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  // Read lazily so the secret can be configured after import (e.g. in tests).
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET,
  // Bind the token to the logged-in session (the JWT auth cookie).
  getSessionIdentifier: (req) => req.cookies?.token || '',
  cookieName: 'x-csrf-token',
  cookieOptions: {
    sameSite: 'lax',
    path: '/',
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true
  },
  // Safe methods are never checked.
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],
  // Pre-auth routes run before a session exists.
  skipCsrfProtection: (req) =>
    req.path === '/api/auth/login' || req.path === '/api/auth/register'
});

// GET /api/csrf-token: issue a token for the current session.
export function csrfTokenHandler(req, res) {
  res.json({ csrfToken: generateCsrfToken(req, res, { overwrite: true }) });
}

export { doubleCsrfProtection };
