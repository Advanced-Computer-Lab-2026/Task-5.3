import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { getSettings, updateRecoveryEmail } from '../controllers/settingController.js';

const router = Router();

// Reading and writing both require a logged-in user. The write is also guarded
// by the global CSRF middleware in app.js (token must be echoed in x-csrf-token).
router.get('/', requireAuth, getSettings);
router.post('/recovery-email', requireAuth, updateRecoveryEmail);

export default router;
