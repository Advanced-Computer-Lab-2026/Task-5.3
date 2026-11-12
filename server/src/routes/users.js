import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { csrfProtection } from '../middleware/csrf.js';
import {
  getAllUsers,
  getUser,
  updateUser,
  deleteUser
} from '../controllers/userController.js';

const router = Router();

// Creating a user is now done through POST /api/auth/register.
router.get('/', getAllUsers);
router.get('/:id', getUser);
router.patch('/:id', requireAuth, csrfProtection, updateUser);
router.delete('/:id', requireAuth, csrfProtection, deleteUser);

export default router;
