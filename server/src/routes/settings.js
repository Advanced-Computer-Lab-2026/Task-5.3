import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { getSettings, updateRecoveryEmail } from '../controllers/settingController.js';

const router = Router();

// Reading and writing both require a logged-in user. The write is also protected
// against CSRF by the app-wide `csrfProtection` middleware (see app.js), which
// runs before this router and rejects requests without a valid x-csrf-token.
router.get('/', requireAuth, getSettings);
router.post('/recovery-email', requireAuth, updateRecoveryEmail);

export default router;
