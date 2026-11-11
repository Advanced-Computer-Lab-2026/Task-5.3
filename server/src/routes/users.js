
import { Router } from 'express';

import { requireAuth } from '../middleware/auth.js';
import { requireCsrfToken } from '../middleware/csrf.js';

import {
  getAllUsers,
  getUser,
  updateUser,
  deleteUser
} from '../controllers/userController.js';

const router = Router();

router.get('/', getAllUsers);
router.get('/:id', getUser);

router.patch('/:id', requireAuth, requireCsrfToken, updateUser);

router.delete('/:id', requireAuth, requireCsrfToken, deleteUser);

export default router;
