import { doubleCsrf } from 'csrf-csrf';

const csrfSecret = () => process.env.CSRF_SECRET || process.env.JWT_SECRET;

const {
  generateCsrfToken,
  doubleCsrfProtection
} = doubleCsrf({
  getSecret: csrfSecret,
  // Bind the CSRF token to the JWT cookie that identifies this login session.
  getSessionIdentifier: (req) => req.cookies?.token || '',
  cookieName: 'csrfToken',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/'
  },
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token']
});

export function issueCsrfToken(req, res) {
  res.json({ csrfToken: generateCsrfToken(req, res) });
}

export function csrfProtection(req, res, next) {
  // These routes run before a logged-in session exists.
  if (req.method === 'POST' && ['/api/auth/login', '/api/auth/register'].includes(req.path)) {
    return next();
  }

  return doubleCsrfProtection(req, res, next);
}
