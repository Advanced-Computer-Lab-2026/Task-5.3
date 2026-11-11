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

// --- Anti-CSRF protection (double-submit-cookie pattern via csrf-csrf) ---
//
// The auth cookie alone is not proof that a request came from our own app, because
// the browser attaches it to ANY cross-site request. So every state-changing request
// must also carry a secret CSRF token that the attacker's page cannot read or guess.
// The token is handed out by GET /api/csrf-token (which also sets a matching cookie);
// doubleCsrfProtection then checks, on each mutating request, that the token in the
// `x-csrf-token` header matches the one in the cookie.
const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,
  // Binds the token to the current session (the auth cookie). Empty before login.
  getSessionIdentifier: (req) => req.cookies?.token || '',
  cookieName: 'csrf-token',
  cookieOptions: { sameSite: 'lax', secure: false, path: '/' },
  // The client echoes the token back in this header on every write.
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],
});

app.get('/api/health', (req, res) => res.json({ ok: true }));

// Safe GET: hand the client a fresh CSRF token (and set the matching cookie).
app.get('/api/csrf-token', (req, res) => {
  const csrfToken = generateCsrfToken(req, res);
  res.json({ csrfToken });
});

// Pre-auth routes run BEFORE a session exists (login/register) or simply end it
// (logout), so they are mounted ahead of the CSRF gate and stay exempt. Their
// GET route (/me) is a safe method and is ignored by the protection anyway.
app.use('/api/auth', authRoutes);

// From here down, every state-changing request (POST/PUT/PATCH/DELETE) must carry
// a valid CSRF token. Safe methods (GET/HEAD/OPTIONS) are ignored automatically.
app.use(doubleCsrfProtection);

app.use('/api/items', itemRoutes);
app.use('/api/users', userRoutes);
app.use('/api/settings', settingRoutes);

// Not found
app.use((req, res) => {
  res.status(404).json({ message: 'Not Found' });
});

// Error handler. A missing/invalid CSRF token throws a ForbiddenError whose
// `status` is 403, so the forged request is answered with 403 and never reaches
// the controller — the recovery email is left untouched.
app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.status || 500).json({ message: err.message || 'Server Error' });
});

export default app;