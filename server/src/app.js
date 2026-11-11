
import express from 'express';
import morgan from 'morgan';
import cors from 'cors';
import cookieParser from 'cookie-parser';

import authRoutes from './routes/auth.js';
import itemRoutes from './routes/items.js';
import userRoutes from './routes/users.js';
import settingRoutes from './routes/settings.js';

import {
  csrfProtection,
  csrfTokenHandler,
} from './middleware/csrf.js';

const app = express();

app.use(morgan('dev'));

app.use(cors({
  origin: 'http://localhost:5175',
  credentials: true,
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Health check
app.get('/api/health', (req, res) => {
  res.json({ ok: true });
});

// CSRF token endpoint
app.get('/api/csrf-token', csrfTokenHandler);

// Protect state-changing requests.
app.use(csrfProtection);

// API routes
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
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({
      message: 'Invalid or missing CSRF token',
    });
  }

  console.error(err);

  res.status(err.status || 500).json({
    message: err.message || 'Server Error',
  });
});

export default app;
