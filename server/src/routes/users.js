
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

// Reading is public; modifying users requires authentication and CSRF protection.
router.get('/', getAllUsers);
router.get('/:id', getUser);

router.patch('/:id', requireAuth, doubleCsrfProtection, updateUser);
router.delete('/:id', requireAuth, doubleCsrfProtection, deleteUser);

export default router;
