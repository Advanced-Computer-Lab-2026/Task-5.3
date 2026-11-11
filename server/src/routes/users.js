
import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { doubleCsrfProtection } from '../middleware/csrf.js';

import {
  getAllUsers,
  getUser,
  updateUser,
  deleteUser
} from '../controllers/userController.js';

const router = Router();

// Read operations — no CSRF token needed
router.get('/', getAllUsers);
router.get('/:id', getUser);

// Authenticated write operations — CSRF protection required
router.patch('/:id', requireAuth, doubleCsrfProtection, updateUser);

router.delete('/:id', requireAuth, doubleCsrfProtection, deleteUser);

export default router;
