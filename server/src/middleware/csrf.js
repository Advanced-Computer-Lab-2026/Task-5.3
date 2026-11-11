
import { doubleCsrf } from 'csrf-csrf';
import { createHash } from 'node:crypto';

function getSessionIdentifier(req) {
  const token = req.cookies?.token;

  if (!token || !req.user) {
    throw new Error('Authenticated session required');
  }

  return createHash('sha256')
    .update(token)
    .digest('hex');
}

export const {
  generateCsrfToken,
  doubleCsrfProtection
} = doubleCsrf({
  getSecret: () => {
    const secret = process.env.CSRF_SECRET;

    if (!secret) {
      throw new Error('CSRF_SECRET is not configured');
    }

    return secret;
  },

  getSessionIdentifier,

  getTokenFromRequest: (req) =>
    req.headers['x-csrf-token'],

  cookieName: 'csrf-token',

  cookieOptions: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/'
  }
});
