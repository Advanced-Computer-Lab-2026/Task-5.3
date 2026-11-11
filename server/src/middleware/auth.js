import jwt from 'jsonwebtoken';

export function requireAuth(req, res, next) {
  // The JWT now rides in an httpOnly cookie instead of the Authorization header.
  // The browser attaches it automatically on every request to this origin —
  // which is exactly what makes cross-site request forgery (CSRF) possible.
  const token = req.cookies?.token;
  if (!token) return res.status(401).json({ message: 'Missing token' });

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload;
    return next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
}
