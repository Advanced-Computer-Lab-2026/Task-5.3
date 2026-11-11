import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { doubleCsrfProtection } from '../middleware/csrf.js';
import { getSettings, updateRecoveryEmail } from '../controllers/settingController.js';

const router = Router();

router.get('/', requireAuth, getSettings);
router.post('/recovery-email', requireAuth, doubleCsrfProtection, updateRecoveryEmail);

export default router;
