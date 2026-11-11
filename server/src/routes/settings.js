import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { getSettings, updateRecoveryEmail } from '../controllers/settingController.js';
import { doubleCsrfProtection } from '../config/csrf.js';

const router = Router();

router.get('/', requireAuth, getSettings);
router.post('/recovery-email', requireAuth, doubleCsrfProtection, updateRecoveryEmail);

export default router;
