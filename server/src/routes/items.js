
import { Router } from 'express';

import { requireAuth } from '../middleware/auth.js';
import { requireCsrfToken } from '../middleware/csrf.js';

import {
  getAllItems,
  getItem,
  createItem,
  updateItem,
  deleteItem
} from '../controllers/itemController.js';

const router = Router();

router.get('/', getAllItems);
router.get('/:id', getItem);

router.post('/', requireAuth, requireCsrfToken, createItem);

router.patch('/:id', requireAuth, requireCsrfToken, updateItem);

router.delete('/:id', requireAuth, requireCsrfToken, deleteItem);

export default router;
