import { doubleCsrf } from 'csrf-csrf';

const {
  generateCsrfToken,
  doubleCsrfProtection
} = doubleCsrf({
  // Secret used to sign and verify CSRF tokens.
  getSecret: () => process.env.CSRF_SECRET,

  // Bind each CSRF token to the authenticated JWT session.
  getSessionIdentifier: (req) => req.cookies.token,

  // Cookie containing the signed CSRF token.
  cookieName: 'csrf-token',

  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false,
    path: '/'
  },

  // Methods that don't change server data.
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],

  // The frontend must explicitly send the token in this header.
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token']
});

export { generateCsrfToken, doubleCsrfProtection };
