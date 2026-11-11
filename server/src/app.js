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

// CSRF protection (double-submit cookie). The server issues a signed token tied
// to the current session; the client must echo it back in the `x-csrf-token`
// header on every state-changing request. A cross-site attacker can make the
// browser send our cookies, but cannot read the token (CORS blocks reading the
// response) and a plain HTML form cannot set custom headers — so forged
// requests fail with 403.
const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  // Read lazily so the secret is picked up even if env is set after import.
  getSecret: () => process.env.CSRF_SECRET,
  // Bind each token to the logged-in session (the auth cookie).
  getSessionIdentifier: (req) => req.cookies?.token ?? '',
  // No `__Host-` prefix: that requires `Secure`, which needs HTTPS (dev is http).
  cookieName: 'x-csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false, // true in production (HTTPS only)
    path: '/'
  },
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token']
});

app.get('/api/health', (req, res) => res.json({ ok: true }));

// Safe GET that hands the client its CSRF token (and sets the paired cookie).
app.get('/api/csrf-token', (req, res) => {
  const csrfToken = generateCsrfToken(req, res);
  res.json({ csrfToken });
});

// Pre-auth routes (login/register) run before a session exists, so they are
// mounted BEFORE the CSRF middleware and stay exempt.
app.use('/api/auth', authRoutes);

// Everything below requires a valid CSRF token on POST/PUT/PATCH/DELETE.
// GET/HEAD/OPTIONS are ignored by default, so reads keep working.
// An invalid/missing token throws an error with status 403, which the error
// handler at the bottom turns into a 403 response.
app.use(doubleCsrfProtection);

app.use('/api/items', itemRoutes);
app.use('/api/users', userRoutes);
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
