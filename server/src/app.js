import express from 'express';
import morgan from 'morgan';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import authRoutes from './routes/auth.js';
import itemRoutes from './routes/items.js';
import userRoutes from './routes/users.js';
import settingRoutes from './routes/settings.js';
import { doubleCsrf } from 'csrf-csrf';
import { requireAuth } from './middleware/auth.js';
import crypto from 'crypto';

const app = express();
const isProd = process.env.NODE_ENV === 'production';

app.use(morgan('dev'));
// The browser must be allowed to send the auth cookie on cross-origin XHR,
// so CORS is locked to the client origin AND credentials are enabled.
app.use(cors({ origin: 'http://localhost:5175', credentials: true }));
app.use(express.json());
// Parse HTML-form bodies too. A classic CSRF payload is an auto-submitting
// <form> (application/x-www-form-urlencoded), so the endpoints must understand it.
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ── 1. Ensure a stable per-session identifier exists ──
// csrf-csrf requires getSessionIdentifier to bind the token to a session.
// Since you don't use express-session, we create a lightweight cookie for it.
app.use((req, res, next) => {
  if (!req.cookies['csrf_session_id']) {
    const id = crypto.randomUUID(); // Node 19+; or use uuidv4()
    res.cookie('csrf_session_id', id, {
      httpOnly: true,
      sameSite: 'lax',
      secure: isProd,
      path: '/',
      maxAge: 24 * 60 * 60 * 1000, // 24h
    });
    req.cookies['csrf_session_id'] = id; // make it visible to this request
  }
  next();
});

// ── 2. Configure csrf-csrf ──
const { generateCsrfToken, doubleCsrfProtection, invalidCsrfTokenError } =
  doubleCsrf({
    getSecret: () => process.env.CSRF_SECRET, // use a strong, unique secret
    getSessionIdentifier: (req) => req.cookies['csrf_session_id'],
    // Read the token from exactly one place—never fall through to body.
    getTokenFromRequest: (req) => req.headers['x-csrf-token'] ?? '',
    cookieName: isProd ? '__Host-psifi.x-csrf-token' : 'psifi.x-csrf-token',
    cookieOptions: {
      httpOnly: true,
      sameSite: 'lax',
      secure: isProd,
      path: '/',
    },
  });

app.get('/api/health', (req, res) => res.json({ ok: true }));
app.get('/api/csrf-token', (req, res) => {
  const csrfToken = generateCsrfToken(req, res);
  res.json({ csrfToken });
});
app.use('/api/auth', authRoutes);
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
  if (err === invalidCsrfTokenError) {
    return res.status(403).json({ message: 'Invalid CSRF token' });
  }
  console.error(err);
  res.status(err.status || 500).json({ message: err.message || 'Server Error' });
});

export default app;
