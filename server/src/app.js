import express from 'express';
import morgan from 'morgan';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import authRoutes from './routes/auth.js';
import itemRoutes from './routes/items.js';
import userRoutes from './routes/users.js';
import settingRoutes from './routes/settings.js';
import { generateCsrfToken, doubleCsrfProtection } from './config/csrf.js';

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

// The client calls this first to get a CSRF token (also sets the csrf cookie).
app.get('/api/csrf-token', (req, res) => {
  res.json({ csrfToken: generateCsrfToken(req, res) });
});

// Protect every write request (POST/PUT/DELETE).
// GET/HEAD/OPTIONS are safe and are skipped by the library automatically.
// Login and register are exempt: no session exists yet, so there is nothing to forge.
const CSRF_EXEMPT = ['/api/auth/login', '/api/auth/register'];
app.use((req, res, next) => {
  if (CSRF_EXEMPT.includes(req.path)) return next();
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
  console.error(err);
  res.status(err.status || 500).json({ message: err.message || 'Server Error' });
});

export default app;
