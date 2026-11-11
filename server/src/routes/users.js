import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import {
  getAllUsers,
  getUser,
  updateUser,
  deleteUser
} from '../controllers/userController.js';
import { doubleCsrfProtection } from '../middleware/csrf.js';

const router = Router();

// Creating a user is now done through POST /api/auth/register.
router.get('/', getAllUsers);
router.get('/:id', getUser);
router.patch('/:id', requireAuth, doubleCsrfProtection, updateUser);
router.delete('/:id', requireAuth, doubleCsrfProtection, deleteUser);

export default router;
