import { doubleCsrf } from 'csrf-csrf';

// Pre-auth routes run before a session exists, so there is nothing to forge yet.
const EXEMPT_PATHS = new Set(['/api/auth/login', '/api/auth/register']);

const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  // Read lazily so the secret is picked up after dotenv has loaded.
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET || 'dev-only-csrf-secret',
  // Bind the token to the logged-in session (the auth cookie), so a token
  // issued to one user/session is useless for any other.
  getSessionIdentifier: (req) => req.cookies?.token || '',
  cookieName: 'psifi.x-csrf-token',
  cookieOptions: {
    sameSite: 'lax',
    path: '/',
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true
  },
  // Safe methods (GET/HEAD/OPTIONS) are never state-changing, so they are exempt by default.
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],
  skipCsrfProtection: (req) => EXEMPT_PATHS.has(req.originalUrl.split('?')[0]),
  errorConfig: { statusCode: 403, message: 'Invalid or missing CSRF token', code: 'EBADCSRFTOKEN' }
});

export { generateCsrfToken, doubleCsrfProtection };
