
import { doubleCsrf } from 'csrf-csrf';

const {
  generateToken,
  doubleCsrfProtection
} = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,
  getSessionIdentifier: (req) => req.user.id,
  cookieName: 'csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false,
    path: '/'
  },
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  getTokenFromRequest: (req) => req.headers['x-csrf-token']
});

export { generateToken, doubleCsrfProtection };
