
import jwt from 'jsonwebtoken';

export function requireAuth(req, res, next) {
  // Read the JWT from the httpOnly authentication cookie.
  const token = req.cookies?.token;

  if (!token) {
    return res.status(401).json({
      message: 'Missing token',
    });
  }

  try {
    const payload = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    req.user = payload;

    return next();
  } catch (error) {
    return res.status(401).json({
      message: 'Invalid or expired token',
    });
  }
}
