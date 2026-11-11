
import { doubleCsrf } from 'csrf-csrf';

const {
  generateCsrfToken,
  doubleCsrfProtection
} = doubleCsrf({
  getSecret: () => {
    if (!process.env.CSRF_SECRET) {
      throw new Error('CSRF_SECRET must be configured in the server environment');
    }
    return process.env.CSRF_SECRET;
  },

  getSessionIdentifier: (req) => req.cookies.token,

  cookieName: 'csrf-token',

  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/'
  },

  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],

  ignoredMethods: ['GET', 'HEAD', 'OPTIONS']
});

export function issueCsrfToken(req, res) {
  const csrfToken = generateCsrfToken(req, res);
  res.json({ csrfToken });
}

export function requireCsrfToken(req, res, next) {
  doubleCsrfProtection(req, res, (err) => {
    if (err) {
      return res.status(403).json({
        message: 'Invalid or missing CSRF token'
      });
    }

    return next();
  });
}
