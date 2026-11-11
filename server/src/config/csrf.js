import { doubleCsrf } from 'csrf-csrf';
import { randomBytes } from 'node:crypto';

const developmentSecret = randomBytes(32).toString('hex');

const { doubleCsrfProtection, generateCsrfToken } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || developmentSecret,
  getSessionIdentifier: (req) => req.cookies.token,
  cookieName: 'csrf',
  cookieOptions: {
    sameSite: 'lax',
    secure: false,
    httpOnly: true,
    path: '/'
  },
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS']
});

export { doubleCsrfProtection, generateCsrfToken };
