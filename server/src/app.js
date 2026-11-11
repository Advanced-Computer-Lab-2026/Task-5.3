import express from 'express';
import morgan from 'morgan';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import authRoutes from './routes/auth.js';
import itemRoutes from './routes/items.js';
import userRoutes from './routes/users.js';
import settingRoutes from './routes/settings.js';
import { csrfProtection, csrfTokenHandler, csrfErrorHandler } from './middleware/csrf.js';

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

// The client fetches a CSRF token here (a GET, so it is not itself protected)
// and echoes it in the `x-csrf-token` header on every state-changing request.
app.get('/api/csrf-token', csrfTokenHandler);

// Require a valid CSRF token on every state-changing request (POST/PATCH/PUT/
// DELETE). Safe methods and the pre-auth login/register routes are exempt.
// CORS and SameSite=Lax are NOT enough on their own: CORS only stops the
// attacker from reading the response (the forged write still happens), and
// SameSite keys off the site, not the port — localhost:1337 → localhost:4000 is
// "same-site", so the auth cookie is still sent.
app.use(csrfProtection);

app.use('/api/auth', authRoutes);
app.use('/api/items', itemRoutes);
app.use('/api/users', userRoutes);
app.use('/api/settings', settingRoutes);

// Not found
app.use((req, res) => {
  res.status(404).json({ message: 'Not Found' });
});

// A missing/invalid CSRF token → 403 Forbidden.
app.use(csrfErrorHandler);

// Error handler
app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.status || 500).json({ message: err.message || 'Server Error' });
});

export default app;
