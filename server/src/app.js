import express from 'express';
import morgan from 'morgan';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import authRoutes from './routes/auth.js';
import itemRoutes from './routes/items.js';
import userRoutes from './routes/users.js';
import settingRoutes from './routes/settings.js';
import { doubleCsrfProtection, generateCsrfToken } from './middleware/csrf.js';

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

// Issue a CSRF token tied to the current session. The client calls this and
// echoes the token in the `x-csrf-token` header on every mutating request.
app.get('/api/csrf-token', (req, res) => {
  res.json({ csrfToken: generateCsrfToken(req, res) });
});

// Login/register run before a session exists (and logout only clears the
// cookie), so the auth routes stay exempt from the CSRF check.
app.use('/api/auth', authRoutes);

// Every route below this line requires a valid CSRF token on POST/PATCH/PUT/DELETE.
// Safe methods (GET/HEAD/OPTIONS) pass straight through.
app.use(doubleCsrfProtection);

app.use('/api/items', itemRoutes);
app.use('/api/users', userRoutes);
app.use('/api/settings', settingRoutes);

// Not found
app.use((req, res) => {
  res.status(404).json({ message: 'Not Found' });
});

// Error handler
app.use((err, req, res, next) => {
  // A rejected CSRF token is an expected 403, not a server fault — don't dump a stack trace.
  if (err.code !== 'EBADCSRFTOKEN') console.error(err);
  res.status(err.status || 500).json({ message: err.message || 'Server Error' });
});

export default app;
