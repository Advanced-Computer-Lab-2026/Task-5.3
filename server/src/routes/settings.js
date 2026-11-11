import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { getSettings, updateRecoveryEmail } from '../controllers/settingController.js';

const router = Router();

// Reading and writing both require a logged-in user. The write is also
// protected against CSRF: app.js runs `doubleCsrfProtection` (csrf-csrf) before
// this router, so a POST without a valid x-csrf-token header gets a 403.
router.get('/', requireAuth, getSettings);
router.post('/recovery-email', requireAuth, updateRecoveryEmail);

export default router;
