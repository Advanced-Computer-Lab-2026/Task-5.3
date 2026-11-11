import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { getSettings, updateRecoveryEmail } from '../controllers/settingController.js';

const router = Router();

// Reading and writing both require a logged-in user. The write is also guarded
// by the global `doubleCsrfProtection` middleware mounted in app.js, so it only
// succeeds when the request carries a valid `x-csrf-token` header.
router.get('/', requireAuth, getSettings);
router.post('/recovery-email', requireAuth, updateRecoveryEmail);

export default router;
