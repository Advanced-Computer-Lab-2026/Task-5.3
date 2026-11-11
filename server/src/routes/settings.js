import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { getSettings, updateRecoveryEmail } from '../controllers/settingController.js';
import { doubleCsrfProtection } from '../middleware/csrf.js';

const router = Router();

// Reading only needs authentication. The recovery-email write also needs a
// session-bound CSRF token so a third-party page cannot submit it blindly.
router.get('/', requireAuth, getSettings);
router.post('/recovery-email', requireAuth, doubleCsrfProtection, updateRecoveryEmail);

export default router;
