import express from 'express';
import morgan from 'morgan';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { doubleCsrf } from 'csrf-csrf';
import authRoutes from './routes/auth.js';
import itemRoutes from './routes/items.js';
import userRoutes from './routes/users.js';
import settingRoutes from './routes/settings.js';

const app = express();

app.use(morgan('dev'));
app.use(cors({ origin: 'http://localhost:5175', credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// CSRF Configuration
const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => process.env.JWT_SECRET || 'secret',
  cookieName: 'x-csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false, 
  },
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  // 1. Tell it to look for the token in our specific custom header
  getTokenFromRequest: (req) => req.headers['x-csrf-token'],
  // 2. Tell it to identify the user's session using your JWT cookie
  getSessionIdentifier: (req) => req.cookies?.token || 'guest-session',
});

// Endpoint for the React client to request a CSRF token
app.get('/api/csrf-token', (req, res) => {
  res.json({ csrfToken: generateCsrfToken(req, res) });
});

app.get('/api/health', (req, res) => res.json({ ok: true }));

// Pre-auth routes are exempt
app.use('/api/auth', authRoutes);

// Protected routes
app.use('/api/items', doubleCsrfProtection, itemRoutes);
app.use('/api/users', doubleCsrfProtection, userRoutes);
app.use('/api/settings', doubleCsrfProtection, settingRoutes);

app.use((req, res) => {
  res.status(404).json({ message: 'Not Found' });
});

app.use((err, req, res, next) => {
  console.error(err);
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ message: 'Invalid CSRF token' });
  }
  res.status(err.status || 500).json({ message: err.message || 'Server Error' });
});

export default app;