import express from 'express';
import morgan from 'morgan';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import authRoutes from './routes/auth.js';
import itemRoutes from './routes/items.js';
import userRoutes from './routes/users.js';
import settingRoutes from './routes/settings.js';
import { csrfProtection, csrfTokenHandler } from './middleware/csrf.js';

const app = express();

app.use(morgan('dev'));
// The browser must be allowed to send the auth cookie on cross-origin XHR,
// so CORS is locked to the client origin AND credentials are enabled.
app.use(cors({
  origin: 'http://localhost:5175',
  credentials: true,
  // The client echoes the CSRF token in this custom header.
  allowedHeaders: ['Content-Type', 'x-csrf-token']
}));
app.use(express.json());
// Parse HTML-form bodies too. A classic CSRF payload is an auto-submitting
// <form> (application/x-www-form-urlencoded), so the endpoints must understand it.
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.get('/api/health', (req, res) => res.json({ ok: true }));

// CSRF: the client fetches a token here, then sends it back in the
// `x-csrf-token` header on every state-changing request.
app.get('/api/csrf-token', csrfTokenHandler);

// Every POST/PUT/PATCH/DELETE below this line must carry a valid CSRF token.
// Safe methods (GET/HEAD/OPTIONS) and login/register are exempt.
app.use(csrfProtection);

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
  // Missing/invalid CSRF token -> 403 Forbidden (the forged request is refused).
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ message: 'Invalid or missing CSRF token' });
  }
  console.error(err);
  res.status(err.status || 500).json({ message: err.message || 'Server Error' });
});

export default app;
