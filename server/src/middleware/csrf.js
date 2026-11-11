import { doubleCsrf } from "csrf-csrf";

const { generateCsrfToken, doubleCsrfProtection, invalidCsrfTokenError } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,
  getSessionIdentifier: (req) => req.cookies?.token ?? "",
  cookieName: "csrf_token",
  cookieOptions: { sameSite: "lax", secure: process.env.NODE_ENV === "production", httpOnly: true, path: "/" },
  getCsrfTokenFromRequest: (req) => req.headers["x-csrf-token"],
  ignoredMethods: ["GET", "HEAD", "OPTIONS"],
});

export { generateCsrfToken, doubleCsrfProtection };

export function csrfErrorHandler(err, req, res, next) {
  if (err === invalidCsrfTokenError) {
    return res.status(403).json({ message: "Invalid or missing CSRF token" });
  }
  next(err);
}