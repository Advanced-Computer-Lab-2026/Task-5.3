import { doubleCsrf } from 'csrf-csrf';

// Pre-auth routes run before a session exists, so there is nothing to forge yet
// (and no token could have been bound to a session). They stay exempt.
const EXEMPT_PATHS = new Set(['/api/auth/login', '/api/auth/register']);

const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  // Secret used to HMAC the token. Read lazily so tests/env can set it after import.
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET || 'dev-csrf-secret',
  // Bind the token to the logged-in session: a token minted for one user's
  // auth cookie is worthless for any other session.
  getSessionIdentifier: (req) => req.cookies?.token || '',
  cookieName: 'csrf_token',
  cookieOptions: {
    sameSite: 'lax',
    secure: false, // true in production (HTTPS only)
    httpOnly: true,
    path: '/'
  },
  // The client echoes the token back in this header; a cross-site form cannot set it.
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],
  errorConfig: { statusCode: 403, message: 'Invalid or missing CSRF token', code: 'EBADCSRFTOKEN' },
  // GET/HEAD/OPTIONS are ignored by default; additionally exempt pre-auth routes.
  skipCsrfProtection: (req) => EXEMPT_PATHS.has(req.originalUrl.split('?')[0])
});

export { generateCsrfToken, doubleCsrfProtection };

// GET /api/csrf-token — hands the client a token and sets the matching cookie.
export function csrfTokenHandler(req, res) {
  res.json({ csrfToken: generateCsrfToken(req, res) });
}
