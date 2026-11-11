import { doubleCsrf } from 'csrf-csrf';

const {
  generateCsrfToken,
  doubleCsrfProtection
} = doubleCsrf({
  // Secret used to sign the token. Read it lazily (inside a function)
  // so it works even when the env var is set after this file loads.
  getSecret: () => process.env.CSRF_SECRET,

  // Tie the token to the logged-in session (the auth cookie).
  // A token from one user can't be used by another user.
  getSessionIdentifier: (req) => req.cookies?.token || '',

  // The default cookie name needs HTTPS. Use a plain name for localhost.
  cookieName: 'csrf_secret',
  cookieOptions: {
    sameSite: 'lax',
    secure: false, // true in production (HTTPS only)
    httpOnly: true,
    path: '/'
  },

  // The client must send the token in this header.
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token']
});

export { generateCsrfToken, doubleCsrfProtection };