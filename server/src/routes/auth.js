
import { Router } from 'express';

import {
  register,
  login,
  logout,
  me
} from '../controllers/authController.js';

import { requireAuth } from '../middleware/auth.js';
import { doubleCsrfProtection } from '../middleware/csrf.js';

const router = Router();

// Public authentication endpoints
router.post('/register', register);
router.post('/login', login);

// Logout changes authentication state,
// so require authentication and CSRF validation.
router.post('/logout', requireAuth, doubleCsrfProtection, logout);

// Reading the current user does not change server state
router.get('/me', requireAuth, me);

export default router;
