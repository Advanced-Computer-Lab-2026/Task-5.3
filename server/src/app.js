import express from 'express';
import morgan from 'morgan';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import authRoutes from './routes/auth.js';
import itemRoutes from './routes/items.js';
import userRoutes from './routes/users.js';
import settingRoutes from './routes/settings.js';
import { csrfTokenHandler, doubleCsrfProtection } from './middleware/csrf.js';

const app = express();

app.use(morgan('dev'));
// CORS locked to the client origin, credentials enabled, and the custom
// CSRF header allowed. (CORS alone does NOT stop CSRF: it only blocks reading
// the response, the request is still sent and executed.)
app.use(cors({
  origin: 'http://localhost:5175',
  credentials: true,
  allowedHeaders: ['Content-Type', 'x-csrf-token'],
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.get('/api/health', (req, res) => res.json({ ok: true }));

// Client fetches its CSRF token here (GET = safe, not protected).
app.get('/api/csrf-token', csrfTokenHandler);

// Every POST/PATCH/PUT/DELETE below must carry a valid x-csrf-token header.
// GET/HEAD/OPTIONS and login/register are exempt (see middleware/csrf.js).
app.use(doubleCsrfProtection);

app.use('/api/auth', authRoutes);
app.use('/api/items', itemRoutes);
app.use('/api/users', userRoutes);
app.use('/api/settings', settingRoutes);

// Not found
app.use((req, res) => {
  res.status(404).json({ message: 'Not Found' });
});

// Error handler (invalid CSRF token -> 403)
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ message: 'Invalid or missing CSRF token' });
  }
  console.error(err);
  res.status(err.status || err.statusCode || 500).json({ message: err.message || 'Server Error' });
});

export default app;
