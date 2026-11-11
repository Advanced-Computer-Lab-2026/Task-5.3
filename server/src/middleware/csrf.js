import { doubleCsrf } from 'csrf-csrf';

// Double-submit-cookie CSRF protection (csrf-csrf).
// 1. GET /api/csrf-token gives the client a token AND sets a matching httpOnly cookie.
// 2. Every state-changing request must echo the token in the `x-csrf-token` header.
// 3. An attacker's page can make the browser send the cookie, but it can never
//    read the token to put it in the header -> forged request gets 403.
const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET || 'dev-csrf-secret',
  // Bind the token to the logged-in session (the JWT cookie).
  getSessionIdentifier: (req) => req.cookies?.token || '',
  cookieName: 'x-csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false, // true in production (HTTPS only)
    path: '/',
  },
  // Safe methods never change state -> exempt.
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  // Token must come from a custom header (an HTML <form> cannot set headers).
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],
  // Pre-auth routes run before a session exists -> exempt.
  skipCsrfProtection: (req) =>
    ['/api/auth/login', '/api/auth/register'].includes(req.path),
});

// GET /api/csrf-token
export function csrfTokenHandler(req, res) {
  const csrfToken = generateCsrfToken(req, res);
  res.json({ csrfToken });
}

export { doubleCsrfProtection };
