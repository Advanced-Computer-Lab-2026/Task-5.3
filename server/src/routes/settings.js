import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { getSettings, updateRecoveryEmail } from '../controllers/settingController.js';
import { doubleCsrfProtection } from '../middleware/csrf.js';

const router = Router();

// Reads need only authentication. The state-changing route also requires the
// session-bound double-submit token validated by csrf-csrf.
router.get('/', requireAuth, getSettings);
router.post('/recovery-email', requireAuth, doubleCsrfProtection, updateRecoveryEmail);

export default router;
