import express from 'express';
import morgan from 'morgan';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import authRoutes from './routes/auth.js';
import itemRoutes from './routes/items.js';
import userRoutes from './routes/users.js';
import settingRoutes from './routes/settings.js';
import {
  generateCsrfToken,
  doubleCsrfProtection,
  invalidCsrfTokenError,
} from './middleware/csrf.js';

const app = express();

app.use(morgan('dev'));
// CORS controls who can READ responses; it does not stop a cross-site form
// POST from being SENT with the cookie. That's why CSRF tokens are needed.
app.use(
  cors({
    origin: 'http://localhost:5175',
    credentials: true,
    allowedHeaders: ['Content-Type', 'x-csrf-token'],
  })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// Must come BEFORE the CSRF middleware: it reads req.cookies.
app.use(cookieParser());

app.get('/api/health', (req, res) => res.json({ ok: true }));

// Hands the token to our own client. The attacker's page can't read this
// response (CORS), so it can never learn the token.
app.get('/api/csrf-token', (req, res) => {
  res.json({ csrfToken: generateCsrfToken(req, res) });
});

// Every POST/PUT/PATCH/DELETE below must carry a valid x-csrf-token header.
// GET/HEAD/OPTIONS are ignored by default; login/register are exempt.
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
  if (err === invalidCsrfTokenError || err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ message: 'Invalid or missing CSRF token' });
  }
  console.error(err);
  res.status(err.status || 500).json({ message: err.message || 'Server Error' });
});

export default app;