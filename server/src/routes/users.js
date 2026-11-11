import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
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
router.patch('/:id', requireAuth, updateUser);
router.delete('/:id', requireAuth, deleteUser);

export default router;
