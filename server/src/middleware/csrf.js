import { doubleCsrf } from 'csrf-csrf';

const {
  generateCsrfToken,
  doubleCsrfProtection
} = doubleCsrf({
  getSecret: () => {
    const secret = process.env.CSRF_SECRET || process.env.JWT_SECRET;
    if (!secret) throw new Error('CSRF_SECRET or JWT_SECRET must be set');
    return secret;
  },
  getSessionIdentifier: (req) => req.user.id,
  cookieName: 'csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    path: '/'
  },
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token']
});

export { doubleCsrfProtection };

export function issueCsrfToken(req, res) {
  const csrfToken = generateCsrfToken(req, res);
  res.json({ csrfToken });
}
