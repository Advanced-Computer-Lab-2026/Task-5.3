
import express from 'express';
import morgan from 'morgan';
import cors from 'cors';
import cookieParser from 'cookie-parser';

import authRoutes from './routes/auth.js';
import itemRoutes from './routes/items.js';
import userRoutes from './routes/users.js';
import settingRoutes from './routes/settings.js';

import { requireAuth } from './middleware/auth.js';
import { issueCsrfToken } from './middleware/csrf.js';

const app = express();

app.use(morgan('dev'));

app.use(cors({
  origin: 'http://localhost:5175',
  credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.get('/api/health', (req, res) => {
  res.json({ ok: true });
});

// Generate a CSRF token for authenticated users
app.get('/api/csrf-token', requireAuth, issueCsrfToken);

app.use('/api/auth', authRoutes);
app.use('/api/items', itemRoutes);
app.use('/api/users', userRoutes);
app.use('/api/settings', settingRoutes);

app.use((req, res) => {
  res.status(404).json({ message: 'Not Found' });
});

app.use((err, req, res, next) => {
  console.error(err);

  if (err.code === 'EBADCSRFTOKEN' || err.status === 403) {
    return res.status(403).json({
      message: 'Invalid or missing CSRF token'
    });
  }

  res.status(err.status || 500).json({
    message: err.message || 'Server Error'
  });
});

export default app;
