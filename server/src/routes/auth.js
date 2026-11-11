
import { Router } from 'express';

import {
  register,
  login,
  logout,
  me
} from '../controllers/authController.js';

import { requireAuth } from '../middleware/auth.js';
import { requireCsrfToken } from '../middleware/csrf.js';

const router = Router();

// Login and registration don't require CSRF tokens
router.post('/register', register);
router.post('/login', login);

// Logout requires authentication and CSRF validation
router.post('/logout', requireAuth, requireCsrfToken, logout);

router.get('/me', requireAuth, me);

export default router;
