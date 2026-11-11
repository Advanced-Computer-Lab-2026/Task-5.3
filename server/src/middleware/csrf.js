import { doubleCsrf } from 'csrf-csrf';

// Bind each CSRF token to the user's current JWT cookie. Rotating the JWT on
// login/register therefore invalidates tokens from the previous session.
const csrf = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET,
  getSessionIdentifier: (req) => req.cookies?.token || '',
  cookieName: 'csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    path: '/'
  }
});

export const { generateCsrfToken, doubleCsrfProtection } = csrf;
