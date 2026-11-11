import { doubleCsrf } from "csrf-csrf";

export const {
  generateCsrfToken,
  doubleCsrfProtection,
} = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,
  getSessionIdentifier: (req) => req.cookies?.token ?? "",
  cookieName: "csrf_token",
  cookieOptions: {
    sameSite: "lax",
    path: "/",
    secure: false, 
    httpOnly: true,
  },
  getCsrfTokenFromRequest: (req) => req.headers["x-csrf-token"],
  ignoredMethods: ["GET", "HEAD", "OPTIONS"],
});

const EXEMPT = new Set(["/api/auth/login", "/api/auth/register"]);

export const csrfProtection = (req, res, next) =>
  EXEMPT.has(req.path) ? next() : doubleCsrfProtection(req, res, next);