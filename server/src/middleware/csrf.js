import { doubleCsrf } from 'csrf-csrf';

const preAuthenticationPaths = new Set([
  '/api/auth/login',
  '/api/auth/register'
]);

const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  // Keep the CSRF signing key separate when configured, while remaining
  // compatible with the project's existing JWT_SECRET setup.
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET,
  // A JWT is issued for each login/register session and stored in the
  // httpOnly auth cookie. Binding CSRF tokens to it invalidates old tokens
  // when the session changes.
  getSessionIdentifier: (req) => req.cookies?.token || 'unauthenticated',
  cookieName: 'csrfToken',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    path: '/'
  },
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],
  skipCsrfProtection: (req) => {
    const path = req.path.replace(/\/+$/, '') || '/';
    return (req.method === 'POST' && preAuthenticationPaths.has(path)) || !req.cookies?.token;
  }
});

export const csrfProtection = doubleCsrfProtection;

export function issueCsrfToken(req, res) {
  res.json({ csrfToken: generateCsrfToken(req, res) });
}
