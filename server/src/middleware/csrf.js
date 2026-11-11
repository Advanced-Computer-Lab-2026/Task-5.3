import { doubleCsrf } from 'csrf-csrf';

export const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  // the secret used to sign tokens
  getSecret: () => process.env.CSRF_SECRET,
  // ties the CSRF token to the logged-in user's session (their auth cookie)
  getSessionIdentifier: (req) => req.cookies.token || '',
  cookieName: 'x-csrf-token',
  cookieOptions: { sameSite: 'lax', secure: false, httpOnly: true }
});