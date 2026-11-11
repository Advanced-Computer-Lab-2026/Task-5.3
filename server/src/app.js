import express from 'express';
import morgan from 'morgan';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { doubleCsrf } from 'csrf-csrf';
import authRoutes from './routes/auth.js';
import itemRoutes from './routes/items.js';
import userRoutes from './routes/users.js';
import settingRoutes from './routes/settings.js';

const app = express();

// ---- CSRF protection (double-submit cookie, csrf-csrf v4) -------------------
// The token is bound to the session (the JWT cookie), so a token issued to one
// user/session is useless for another. Secrets are read lazily, per request.
const {
  invalidCsrfTokenError,
  generateCsrfToken,
  doubleCsrfProtection
} = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET,
  getSessionIdentifier: (req) => req.cookies?.token || '',
  cookieName: 'csrf_token', // no "__Host-" prefix: that needs HTTPS, and we run on http://localhost
  cookieOptions: {
    sameSite: 'lax',
    secure: false, // true in production (HTTPS only)
    httpOnly: true,
    path: '/'
  },
  size: 32,
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'], // safe methods never change state
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token']
});

// Pre-auth routes run before any session exists, so there is nothing to forge yet.
const CSRF_EXEMPT = new Set(['/auth/login', '/auth/register']);

app.use(morgan('dev'));
// The browser must be allowed to send the auth cookie on cross-origin XHR,
// so CORS is locked to the client origin AND credentials are enabled.
app.use(cors({ origin: 'http://localhost:5175', credentials: true }));
app.use(express.json());
// Parse HTML-form bodies too. A classic CSRF payload is an auto-submitting
// <form> (application/x-www-form-urlencoded), so the endpoints must understand it.
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.get('/api/health', (req, res) => res.json({ ok: true }));

// The client calls this to obtain a token (also sets the matching csrf cookie).
// A fresh token is minted each time; the client retries once on a 403 if a
// newer token in another tab replaced the cookie.
app.get('/api/csrf-token', (req, res) => {
  const csrfToken = generateCsrfToken(req, res, { overwrite: true });
  res.json({ csrfToken });
});

// Every state-changing /api request must carry a valid token, except pre-auth routes.
app.use('/api', (req, res, next) => {
  if (CSRF_EXEMPT.has(req.path)) return next();
  return doubleCsrfProtection(req, res, next);
});

app.use('/api/auth', authRoutes);
app.use('/api/items', itemRoutes);
app.use('/api/users', userRoutes);
app.use('/api/settings', settingRoutes);

// Not found
app.use((req, res) => {
  res.status(404).json({ message: 'Not Found' });
});

// Error handler
app.use((err, req, res, next) => {
  if (err === invalidCsrfTokenError) {
    return res.status(403).json({ message: 'Invalid or missing CSRF token' });
  }
  console.error(err);
  res.status(err.status || 500).json({ message: err.message || 'Server Error' });
});

export default app;
