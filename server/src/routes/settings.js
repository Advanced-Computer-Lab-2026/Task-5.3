
import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';

import {
  generateCsrfToken,
  doubleCsrfProtection
} from '../middleware/csrf.js';

import {
  getSettings,
  updateRecoveryEmail
} from '../controllers/settingController.js';

const router = Router();

// Generate a CSRF token for the authenticated user.
router.get('/csrf-token', requireAuth, (req, res) => {
  const csrfToken = generateCsrfToken(req, res);

  res.json({ csrfToken });
});

// Reading settings only requires authentication.
router.get('/', requireAuth, getSettings);

// Updating settings requires BOTH authentication and CSRF validation.
router.post(
  '/recovery-email',
  requireAuth,
  doubleCsrfProtection,
  updateRecoveryEmail
);

export default router;
