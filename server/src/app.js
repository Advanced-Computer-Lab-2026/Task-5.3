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
app.use(cors({ origin: 'http://localhost:5175', credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const { doubleCsrfProtection } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || 'test-csrf-secret',
  cookieName: 'x-csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false
  },
  getTokenFromRequest: (req) => req.headers['x-csrf-token'],
  // Add this line so csrf-csrf ties the token to our JWT cookie rather than a missing session object
  getSessionIdentifier: (req) => req.cookies?.token || 'anonymous' 
});
app.get('/api/health', (req, res) => res.json({ ok: true }));

// Pre-auth routes run before CSRF protection (login sets the session cookie)
app.use('/api/auth', authRoutes);

// Apply CSRF protection to all routes below. (By default, it ignores GET, HEAD, OPTIONS)
app.use(doubleCsrfProtection);

// Since doubleCsrfProtection has run, req.csrfToken() is now safely available
app.get('/api/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

app.use('/api/items', itemRoutes);
app.use('/api/users', userRoutes);
app.use('/api/settings', settingRoutes);

// Custom error handler for CSRF failures
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ message: 'Invalid or missing CSRF token' });
  }
  next(err);
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.status || 500).json({ message: err.message || 'Server Error' });
});

export default app;