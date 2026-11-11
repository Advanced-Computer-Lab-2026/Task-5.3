import express from 'express';
import morgan from 'morgan';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import authRoutes from './routes/auth.js';
import itemRoutes from './routes/items.js';
import userRoutes from './routes/users.js';
import settingRoutes from './routes/settings.js';
import { generateCsrfToken, doubleCsrfProtection } from './middleware/csrf.js';

const app = express();

app.use(morgan('dev'));
// The browser must be allowed to send the auth cookie on cross-origin XHR,
// so CORS is locked to the client origin AND credentials are enabled.
app.use(cors({
  origin: 'http://localhost:5175',
  credentials: true,
  allowedHeaders: ['Content-Type', 'X-CSRF-Token']
}));
app.use(express.json());
// Parse HTML-form bodies too. A classic CSRF payload is an auto-submitting
// <form> (application/x-www-form-urlencoded), so the endpoints must understand it.
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.get('/api/health', (req, res) => res.json({ ok: true }));

// Exempt: login/register run before a session exists, so there is nothing to ride on
app.use('/api/auth', authRoutes);

// Hands the client a token (and sets the csrf_token cookie)
app.get('/api/csrf-token', (req, res) => {
  res.json({ csrfToken: generateCsrfToken(req, res) });
});

// Everything below requires a valid token on POST/PUT/PATCH/DELETE
app.use('/api', doubleCsrfProtection);

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
