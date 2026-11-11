import express from 'express';
import morgan from 'morgan';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import authRoutes from './routes/auth.js';
import itemRoutes from './routes/items.js';
import userRoutes from './routes/users.js';
import settingRoutes from './routes/settings.js';

// Import the CSRF middleware you created in Step 2
import { doubleCsrfProtection, generateToken } from './middleware/csrf.js';

const app = express();

app.use(morgan('dev'));
// The browser must be allowed to send the auth cookie on cross-origin XHR,
// so CORS is locked to the client origin AND credentials are enabled.
app.use(cors({ origin: 'http://localhost:5175', credentials: true }));
app.use(express.json());
// Parse HTML-form bodies too. A classic CSRF payload is an auto-submitting
// <form> (application/x-www-form-urlencoded), so the endpoints must understand it.
app.use(express.urlencoded({ extended: true }));

// cookie-parser must run BEFORE the CSRF middleware so it can read the secret cookie
app.use(cookieParser());

// ==========================================
// CSRF PROTECTION SETUP (STEP 3)
// ==========================================

// 1. Endpoint for the React client to fetch the token
app.get('/api/csrf-token', (req, res) => {
  const csrfToken = generateToken(req, res);
  res.json({ csrfToken });
});

// 2. Conditionally apply CSRF protection
app.use((req, res, next) => {
  // Routes that run before a user is authenticated need to be exempt.
  // We check the raw path here.
  const exemptRoutes = ['/api/auth/login', '/api/auth/register'];

  if (exemptRoutes.includes(req.path)) {
    return next(); // Skip CSRF check for login and register
  }

  // doubleCsrfProtection automatically ignores GET, HEAD, and OPTIONS requests,
  // so it will only enforce the token on POST, PUT, DELETE, etc.
  doubleCsrfProtection(req, res, next);
});
// ==========================================

app.get('/api/health', (req, res) => res.json({ ok: true }));

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
  // Handle CSRF validation errors gracefully
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ message: 'Invalid or missing CSRF token' });
  }

  console.error(err);
  res.status(err.status || 500).json({ message: err.message || 'Server Error' });
});

export default app;