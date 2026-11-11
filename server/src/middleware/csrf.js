import { doubleCsrf } from 'csrf-csrf';

export const { doubleCsrfProtection, generateCsrfToken } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,
  // Ties each CSRF token to the session it was issued for — here, the JWT
  // value itself, since there's no server-side session store.
  getSessionIdentifier: (req) => req.cookies?.token || '',
  cookieName: 'csrf-token', // use "__Host-psifi.x-csrf-token" + secure:true once on HTTPS
  cookieOptions: {
    sameSite: 'lax',
    secure: false, // true in production
    httpOnly: true
  },
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token']
});