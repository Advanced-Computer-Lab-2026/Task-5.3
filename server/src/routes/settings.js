import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { getSettings, updateRecoveryEmail } from '../controllers/settingController.js';
import { doubleCsrfProtection } from '../middleware/csrf.js';

const router = Router();

// Reading and writing both require a logged-in user. Nothing here checks that
// the request actually originated from our own app — so the write below is
// vulnerable to CSRF. The solution project adds that check with `csrf-csrf`.
router.get('/', requireAuth, getSettings);
router.post('/recovery-email', requireAuth, doubleCsrfProtection, updateRecoveryEmail);

export default router;
