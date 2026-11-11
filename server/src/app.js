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
app.use(cors({ origin: 'http://localhost:5175', credentials: true }));
app.use(express.json());
// Parse HTML-form bodies too. A classic CSRF payload is an auto-submitting
// <form> (application/x-www-form-urlencoded), so the endpoints must understand it.
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.get('/api/health', (req, res) => res.json({ ok: true }));

// Anti-CSRF: the client fetches a token here, then every write must echo it in
// the x-csrf-token header. Safe methods and login/register are exempt.
app.get('/api/csrf-token', csrfTokenHandler);
app.use('/api', csrfProtection);

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
  const status = err.status || err.statusCode || 500;
  // Only log real server faults. Expected client errors (e.g. a 403 for a
  // missing/invalid CSRF token) are already visible in morgan's request log.
  if (status >= 500) console.error(err);
  res.status(status).json({ message: err.message || 'Server Error' });
});

export default app;
