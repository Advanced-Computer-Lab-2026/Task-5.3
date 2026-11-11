
import { doubleCsrf } from 'csrf-csrf';

const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET,

  getSessionIdentifier: (req) => req.cookies?.token || '',

  cookieName: 'csrf-token',

  cookieOptions: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/'
  },

  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token']
});

export { generateCsrfToken, doubleCsrfProtection };
