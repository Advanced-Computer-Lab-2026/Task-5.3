import { doubleCsrf } from "csrf-csrf";

export const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET,
  getSessionIdentifier: (req) => req.cookies?.token || "",
  cookieName: "x-csrf-token",
  cookieOptions: { sameSite: "lax", secure: false, httpOnly: true, path: "/" },
  getCsrfTokenFromRequest: (req) => req.headers["x-csrf-token"],
});