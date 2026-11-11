import { doubleCsrf } from 'csrf-csrf';

export function assertCsrfSecret() {
  if (!process.env.CSRF_SECRET?.trim()) {
    throw new Error('CSRF_SECRET must be configured with an independent random secret');
  }
}

function cookieOptions() {
  return {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    secure: process.env.NODE_ENV === 'production'
  };
}

const cookieName = process.env.NODE_ENV === 'production' ? '__Host-csrf-token' : 'csrf-token';

const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => {
    assertCsrfSecret();
    return process.env.CSRF_SECRET;
  },
  getSessionIdentifier: (req) => req.cookies.token,
  cookieName,
  cookieOptions: cookieOptions(),
  getCsrfTokenFromRequest: (req) => req.get('x-csrf-token')
});

export { doubleCsrfProtection };

export function issueCsrfToken(req, res) {
  res.set('Cache-Control', 'no-store');
  // Valid cookies are reused; csrf-csrf replaces invalid cookies by default.
  res.json({ csrfToken: generateCsrfToken(req, res) });
}

export function clearCsrfCookie(res, req) {
  if (req && !Object.hasOwn(req.cookies || {}, cookieName)) return;
  res.clearCookie(cookieName, cookieOptions());
}
