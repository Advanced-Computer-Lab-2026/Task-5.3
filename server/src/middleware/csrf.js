
import { doubleCsrf } from "csrf-csrf";

const {
  generateCsrfToken,
  doubleCsrfProtection
} = doubleCsrf({
  // A separate secret used to sign CSRF tokens.
  getSecret: () => process.env.CSRF_SECRET,

  // Each JWT represents a particular login session.
  getSessionIdentifier: (req) => req.cookies.token,

  cookieName: process.env.NODE_ENV === "production"
    ? "__Host-csrf-token"
    : "csrf-token",

  cookieOptions: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/"
  },

  ignoredMethods: ["GET", "HEAD", "OPTIONS"],

  getCsrfTokenFromRequest: (req) => req.headers["x-csrf-token"]
});

export {
  generateCsrfToken,
  doubleCsrfProtection
};
