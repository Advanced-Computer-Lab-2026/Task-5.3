import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { csrfProtection } from '../middleware/csrf.js';
import { getSettings, updateRecoveryEmail } from '../controllers/settingController.js';

const router = Router();

// Reads require authentication. Writes also validate a session-bound CSRF token.
router.get('/', requireAuth, getSettings);
router.post('/recovery-email', requireAuth, csrfProtection, updateRecoveryEmail);

export default router;
