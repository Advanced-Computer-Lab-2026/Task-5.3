import { doubleCsrf } from 'csrf-csrf';

const {
  generateCsrfToken,
  doubleCsrfProtection
} = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,

  // Each login gets a unique session ID inside its JWT.
  getSessionIdentifier: (req) => req.user.sessionId,

  cookieName: 'csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false,
    path: '/'
  },

  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token']
});

export function getCsrfToken(req, res) {
  const csrfToken = generateCsrfToken(req, res);
  res.json({ csrfToken });
}

export { doubleCsrfProtection };