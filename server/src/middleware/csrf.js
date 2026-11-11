import { doubleCsrf } from 'csrf-csrf';

// Double-submit-cookie CSRF protection.
//
// The server hands the client a token (GET /api/csrf-token) and also sets a
// matching HMAC'd copy in a cookie. Every state-changing request must echo the
// token back in the `x-csrf-token` header. A forged cross-site request still
// carries the cookies (the browser sends them for free) but the attacker's page
// can neither read the token nor set a custom header on a plain <form> POST,
// so the check fails with 403.
//
// The token is bound to the session (the auth cookie), so a token issued for
// one login can't be replayed against another.
const { doubleCsrfProtection, generateCsrfToken } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET,
  getSessionIdentifier: (req) => req.cookies?.token || '',
  cookieName: 'x-csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false, // true in production (HTTPS only)
    path: '/'
  },
  // GET/HEAD/OPTIONS are "safe" and never checked.
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token']
});

export { doubleCsrfProtection, generateCsrfToken };
