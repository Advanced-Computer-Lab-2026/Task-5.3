import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { getSettings, updateRecoveryEmail } from '../controllers/settingController.js';

const router = Router();

// Reading and writing both require a logged-in user. The write is also
// protected against CSRF: app.js mounts csrf-csrf's `doubleCsrfProtection`
// before these routes, so a POST without a valid x-csrf-token is rejected (403)
// before it ever reaches updateRecoveryEmail.
router.get('/', requireAuth, getSettings);
router.post('/recovery-email', requireAuth, updateRecoveryEmail);

export default router;
