
import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import {
  getAllItems,
  getItem,
  createItem,
  updateItem,
  deleteItem
} from '../controllers/itemController.js';
import { doubleCsrfProtection } from '../middleware/csrf.js';

const router = Router();

router.get('/', getAllItems);
router.get('/:id', getItem);

router.post('/', requireAuth, doubleCsrfProtection, createItem);
router.patch('/:id', requireAuth, doubleCsrfProtection, updateItem);
router.delete('/:id', requireAuth, doubleCsrfProtection, deleteItem);

export default router;
