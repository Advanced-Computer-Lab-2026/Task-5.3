import { randomBytes } from 'node:crypto';
import { doubleCsrf } from 'csrf-csrf';

const fallbackSecret = randomBytes(32).toString('hex');

const csrfInstance = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || fallbackSecret,
  getSessionIdentifier: (req) => req.cookies.token || '',
  cookieName: "x-csrf-token",
  cookieOptions: {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    secure: process.env.NODE_ENV === "production",
  },
  size: 64,
  ignoredMethods: ["GET", "HEAD", "OPTIONS"],
  getCsrfTokenFromRequest: (req) => req.headers["x-csrf-token"],
});

// Explicitly export each required function
export const doubleCsrfProtection = csrfInstance.doubleCsrfProtection;
export const generateToken = csrfInstance.generateCsrfToken;
