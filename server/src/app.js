import express from 'express';
import morgan from 'morgan';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import authRoutes from './routes/auth.js';
import itemRoutes from './routes/items.js';
import userRoutes from './routes/users.js';
import settingRoutes from './routes/settings.js';
import { doubleCsrfProtection, csrfTokenHandler } from './middleware/csrf.js';

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

// Issue an anti-CSRF token (a GET, so the protection below lets it through).
app.get('/api/csrf-token', csrfTokenHandler);

// Require a valid CSRF token on every state-changing request (POST/PUT/PATCH/
// DELETE) from here on. Safe methods and login/register are exempt (see
// middleware/csrf.js). CORS and SameSite alone are not enough: CORS only stops
// the attacker from reading the response, not from sending the request, and
// SameSite=Lax still sends the cookie from localhost:1337 to localhost:4000
// because ports do not make a different "site".
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
  console.error(err);
  res.status(err.status || 500).json({ message: err.message || 'Server Error' });
});

export default app;
