import { doubleCsrf } from 'csrf-csrf';

// Double-submit-cookie CSRF protection.
// The server issues a token (HMAC'd with CSRF_SECRET and bound to the session),
// stores its hash in a cookie, and requires the same token back in the
// `x-csrf-token` header on every state-changing request. A cross-site attacker
// can make the browser send cookies, but cannot read the token or set a custom
// header on a plain form POST — so their forged request fails with 403.
export const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  // Read lazily so the secret is picked up even if env is set after import.
  getSecret: () => process.env.CSRF_SECRET,
  // Bind the token to the logged-in session (the auth cookie).
  getSessionIdentifier: (req) => req.cookies?.token ?? '',
  // No "__Host-" prefix: that requires HTTPS, and dev runs on http://localhost.
  cookieName: 'x-csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/'
  },
  // Only accept the token from the header — never from a form body.
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token']
  // ignoredMethods defaults to GET, HEAD, OPTIONS: safe reads stay exempt.
});
