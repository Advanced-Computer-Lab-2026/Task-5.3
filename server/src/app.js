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

app.use(morgan('dev'));
// The browser must be allowed to send the auth cookie on cross-origin XHR,
// so CORS is locked to the client origin AND credentials are enabled.
app.use(cors({ origin: 'http://localhost:5175', credentials: true }));
app.use(express.json());
// Parse HTML-form bodies too. A classic CSRF payload is an auto-submitting
// <form> (application/x-www-form-urlencoded), so the endpoints must understand it.
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ─── CSRF protection (double-submit cookie pattern via csrf-csrf) ──────────────
//
// getSecret: a stable, server-side secret used to HMAC-sign the CSRF token.
// getSessionIdentifier: a per-session value that ties each token to a session.
//   We use the auth JWT cookie — a forged cross-site request cannot read it.
// cookieOptions: no "secure: true" so the cookie works over plain http in dev.
// getCsrfTokenFromRequest: we expect the client to send the token in the
//   x-csrf-token header (standard for axios-based SPAs).
const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || 'csrf-dev-secret',
  getSessionIdentifier: (req) => req.cookies?.token ?? '',
  cookieName: 'x-csrf-token',
  cookieOptions: {
    sameSite: 'strict',
    path: '/',
    secure: false,     // set true in production (HTTPS)
    httpOnly: true,
  },
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],
});

app.get('/api/health', (req, res) => res.json({ ok: true }));

// Token-vending endpoint. The client hits this BEFORE any state-changing
// request; we generate a signed CSRF token, set the CSRF cookie, and return
// the token value so the client can echo it in x-csrf-token.
app.get('/api/csrf-token', (req, res) => {
  const csrfToken = generateCsrfToken(req, res);
  res.json({ csrfToken });
});

// Pre-auth routes (no session yet, must NOT be behind CSRF protection).
app.use('/api/auth', authRoutes);
app.use('/api/items', itemRoutes);
app.use('/api/users', userRoutes);

// Apply CSRF protection to all routes registered below this line.
// Settings is the only state-changing, cookie-authenticated endpoint added in
// this task, so it goes after the middleware.
app.use(doubleCsrfProtection);
app.use('/api/settings', settingRoutes);

// Not found
app.use((req, res) => {
  res.status(404).json({ message: 'Not Found' });
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.status || 500).json({ message: err.message || 'Server Error' });
});

export default app;
