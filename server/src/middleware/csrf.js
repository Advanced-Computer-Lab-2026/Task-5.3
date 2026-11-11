import { doubleCsrf } from 'csrf-csrf';

// Routes that run before a session exists: there is nothing to forge yet
// (login CSRF is out of scope here), and the client has no session-bound
// token to send. Everything else that mutates state is protected.
const EXEMPT_PATHS = new Set(['/api/auth/login', '/api/auth/register']);

const { generateCsrfToken, doubleCsrfProtection, invalidCsrfTokenError } = doubleCsrf({
  // Read lazily so the secret can be set after this module is imported.
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET,
  // Bind the token to the session: a token minted for one login is useless
  // with another user's auth cookie.
  getSessionIdentifier: (req) => req.cookies?.token || '',
  cookieName: 'csrf_token',
  cookieOptions: {
    sameSite: 'lax',
    secure: false, // true in production (HTTPS only)
    httpOnly: true,
    path: '/'
  },
  // Default: the token is read from the `x-csrf-token` request header.
  // Safe methods (GET/HEAD/OPTIONS) are ignored by default.
  skipCsrfProtection: (req) => EXEMPT_PATHS.has(req.originalUrl.split('?')[0]),
  errorConfig: { statusCode: 403, message: 'Invalid or missing CSRF token', code: 'EBADCSRFTOKEN' }
});

export { generateCsrfToken, doubleCsrfProtection, invalidCsrfTokenError };

// GET /api/csrf-token — hands the client a token (and sets the paired cookie).
export function csrfTokenHandler(req, res) {
  const csrfToken = generateCsrfToken(req, res, { overwrite: true });
  res.json({ csrfToken });
}
