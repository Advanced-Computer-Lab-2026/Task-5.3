import { doubleCsrf } from 'csrf-csrf';

// Double-submit-cookie CSRF protection (csrf-csrf).
//
// GET /api/csrf-token issues a token of the form "<hmac>.<random>" (the HMAC
// signs the random value + the session id with CSRF_SECRET) and also stores the
// same token in an httpOnly cookie. Every state-changing request must echo the
// token back in the `x-csrf-token` header. The server checks that the header
// equals the cookie AND that the HMAC is valid for the current session.
//
// An attacker's page can make the browser SEND our cookies, but it cannot READ
// the token (CORS blocks reading the response) and an auto-submitting <form>
// cannot set a custom header. So a forged request has no valid token → 403.
export const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  // Read lazily so the secret can be set after this module is imported (tests do this).
  getSecret: () => process.env.CSRF_SECRET,
  // Bind each token to the logged-in session (the JWT auth cookie), so a token
  // from one session cannot be reused with another.
  getSessionIdentifier: (req) => req.cookies?.token ?? '',
  // The default "__Host-" cookie name requires HTTPS; we run over http://localhost.
  cookieName: 'csrf-secret',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false, // true in production (HTTPS only)
    path: '/'
  },
  // GET/HEAD/OPTIONS are "safe" and skipped by default; everything else needs the header.
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token']
});
