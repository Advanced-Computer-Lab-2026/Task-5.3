import express from 'express';
import morgan from 'morgan';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import authRoutes from './routes/auth.js';
import itemRoutes from './routes/items.js';
import userRoutes from './routes/users.js';
import settingRoutes from './routes/settings.js';
import { requireAuth } from './middleware/auth.js';
import { generateCsrfToken, doubleCsrfProtection, CSRF_ERROR_CODE } from './middleware/csrf.js';

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

// Issue the per-session CSRF token. Only a logged-in user has a session to tie it to.
// CORS stops other origins from reading this response, so the attacker never sees it.
app.get('/api/csrf-token', requireAuth, (req, res) => {
  res.json({ csrfToken: generateCsrfToken(req, res) });
});

// Require a valid CSRF token on every state-changing request (POST/PUT/PATCH/DELETE).
// Safe methods (GET/HEAD/OPTIONS) and login/register are skipped (see middleware/csrf.js).
app.use(doubleCsrfProtection);

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
  if (err.code === CSRF_ERROR_CODE) {
    return res.status(403).json({ message: err.message, code: CSRF_ERROR_CODE });
  }
  console.error(err);
  res.status(err.status || 500).json({ message: err.message || 'Server Error' });
});

export default app;
