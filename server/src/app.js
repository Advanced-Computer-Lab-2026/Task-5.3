
import express from 'express';
import morgan from 'morgan';
import cors from 'cors';
import cookieParser from 'cookie-parser';

import authRoutes from './routes/auth.js';
import itemRoutes from './routes/items.js';
import userRoutes from './routes/users.js';
import settingRoutes from './routes/settings.js';

// CSRF protection
import { requireAuth } from './middleware/auth.js';
import { generateCsrfToken } from './middleware/csrf.js';

const app = express();

// Logging
app.use(morgan('dev'));

// Allow the React client to send authentication cookies
app.use(cors({
  origin: 'http://localhost:5175',
  credentials: true
}));

// Parse JSON request bodies
app.use(express.json());

// Parse HTML form submissions
app.use(express.urlencoded({ extended: true }));

// Parse cookies (required for JWT authentication and CSRF)
app.use(cookieParser());

// Health check
app.get('/api/health', (req, res) => {
  res.json({ ok: true });
});

// CSRF TOKEN ENDPOINT
// Only authenticated users can request a CSRF token.
// The token is bound to their current session.
app.get('/api/csrf-token', requireAuth, (req, res) => {
  const csrfToken = generateCsrfToken(req, res);
  res.json({ csrfToken });
});

// Existing API routes
app.use('/api/auth', authRoutes);
app.use('/api/items', itemRoutes);
app.use('/api/users', userRoutes);
app.use('/api/settings', settingRoutes);

// Handle unknown routes
app.use((req, res) => {
  res.status(404).json({
    message: 'Not Found'
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error(err);

  res.status(err.status || err.statusCode || 500).json({
    message: err.message || 'Server Error'
  });
});

export default app;
