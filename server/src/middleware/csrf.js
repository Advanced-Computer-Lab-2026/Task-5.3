
import { doubleCsrf } from 'csrf-csrf';

const {
  generateCsrfToken,
  doubleCsrfProtection
} = doubleCsrf({
  // Keep the documented JWT-only setup working; a separate key can be configured.
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET,
  getSessionIdentifier: (req) => req.cookies?.token || '',
  cookieName: 'csrfToken',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    path: '/'
  },
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token']
});

export { generateCsrfToken, doubleCsrfProtection };
