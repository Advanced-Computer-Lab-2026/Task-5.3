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

const { generateCsrfToken: generateToken, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => process.env.JWT_SECRET,
  getSessionIdentifier: (req) => req.cookies?.token ?? 'anonymous',
  cookieName: '__Host-psifi.x-csrf-token',
  cookieOptions: {
    httpOnly: false,
    sameSite: 'lax',
    secure: true,
    path: '/',
  },
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],
});

app.use(morgan('dev'));
app.use(cors({ origin: 'http://localhost:5175', credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.get('/api/health', (req, res) => res.json({ ok: true }));
app.get('/api/csrf-token', (req, res) => {
  const csrfToken = generateToken(req, res);
  res.json({ csrfToken });
});

app.use('/api', (req, res, next) => {
  const stateChangingMethods = ['POST', 'PUT', 'PATCH', 'DELETE'];
  const isAuthRoute = req.path === '/auth' || req.path.startsWith('/auth/');

  if (!stateChangingMethods.includes(req.method) || isAuthRoute) {
    return next();
  }

  return doubleCsrfProtection(req, res, next);
});

app.use('/api/auth', authRoutes);
app.use('/api/items', itemRoutes);
app.use('/api/users', userRoutes);
app.use('/api/settings', settingRoutes);

app.use((req, res) => {
  res.status(404).json({ message: 'Not Found' });
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.status || 500).json({ message: err.message || 'Server Error' });
});

export default app;
