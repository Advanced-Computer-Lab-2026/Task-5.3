import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { getSettings, updateRecoveryEmail } from '../controllers/settingController.js';

const router = Router();

// Reading and writing both require a logged-in user. The write is also guarded
// against CSRF by the app-wide `doubleCsrfProtection` middleware (see
// middleware/csrf.js), which rejects it with 403 unless it carries a valid
// x-csrf-token header that matches this session's CSRF cookie.
router.get('/', requireAuth, getSettings);
router.post('/recovery-email', requireAuth, updateRecoveryEmail);

export default router;
