
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

// CSRF protection configuration
const {
  generateCsrfToken,
  doubleCsrfProtection
} = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,

  // Bind the CSRF token to the current JWT session.
  getSessionIdentifier: (req) => req.cookies?.token || 'anonymous',

  cookieName: 'csrfToken',

  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/'
  },

  // The frontend sends this header with state-changing requests.
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],

  // Safe methods do not need CSRF protection.
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],

  // Login and registration happen before authentication.
  skipCsrfProtection: (req) => {
    return [
      '/api/auth/login',
      '/api/auth/register'
    ].includes(req.path);
  }
});

// General middleware
app.use(morgan('dev'));

app.use(cors({
  origin: 'http://localhost:5175',
  credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// CSRF middleware must run after cookieParser and before the routes.
app.use(doubleCsrfProtection);

// Endpoint for the frontend to request a CSRF token.
app.get('/api/csrf-token', (req, res) => {
  const csrfToken = generateCsrfToken(req, res);

  res.json({ csrfToken });
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ ok: true });
});

// Application routes
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

  res.status(err.status || 500).json({
    message: err.message || 'Server Error'
  });
});

export default app;
