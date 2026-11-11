import { doubleCsrf } from 'csrf-csrf';

const secure = process.env.NODE_ENV === 'production';

const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET,
  getSessionIdentifier: (req) => req.cookies.token,
  cookieName: secure ? '__Host-csrf-token' : 'csrf-token',
  cookieOptions: { secure, httpOnly: true, sameSite: 'strict', path: '/' },
  getCsrfTokenFromRequest: (req) => req.get('x-csrf-token')
});

export function issueCsrfToken(req, res) {
  res.set('Cache-Control', 'no-store');
  res.json({ csrfToken: generateCsrfToken(req, res) });
}

export { doubleCsrfProtection as requireCsrf };
