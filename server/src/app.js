import express from 'express';
import morgan from 'morgan';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import authRoutes from './routes/auth.js';
import itemRoutes from './routes/items.js';
import userRoutes from './routes/users.js';
import settingRoutes from './routes/settings.js';
import { generateToken, doubleCsrfProtection } from './middleware/csrf.js';

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

app.get('/api/health', (req, res) => res.json({ ok: true }));

// Hand our own client a fresh CSRF token (and set the matching cookie). This is
// a safe GET, so it needs no token itself. The attacker's site cannot read this
// response (CORS/same-origin policy), which is the whole point.
app.get('/api/csrf-token', (req, res) => {
  // csrf-csrf's generateToken is typed (res, req) — response first.
  res.json({ csrfToken: generateToken(res, req) });
});

// Pre-auth routes (register/login/logout) run before a session/CSRF token can
// exist, so they stay exempt.
app.use('/api/auth', authRoutes);

// Every other router performs state-changing writes, so each is guarded by the
// double-submit check. `doubleCsrfProtection` ignores GET/HEAD/OPTIONS, so
// safe reads (e.g. GET /api/settings) still pass through untouched.
app.use('/api/items', doubleCsrfProtection, itemRoutes);
app.use('/api/users', doubleCsrfProtection, userRoutes);
app.use('/api/settings', doubleCsrfProtection, settingRoutes);

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
