import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { generateCsrfToken } from '../middleware/csrf.js';

const router = Router();

router.get('/csrf-token', requireAuth, (req, res) => {
  res.json({ csrfToken: generateCsrfToken(req, res) });
});

export default router;
