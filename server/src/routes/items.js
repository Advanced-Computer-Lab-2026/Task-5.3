import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { requireCsrf } from '../middleware/csrf.js';
import { getAllItems, getItem, createItem, updateItem, deleteItem } from '../controllers/itemController.js';

const router = Router();

// Reading is public; writing requires a logged-in user.
router.get('/', getAllItems);
router.get('/:id', getItem);
router.post('/', requireAuth, requireCsrf, createItem);
router.patch('/:id', requireAuth, requireCsrf, updateItem);
router.delete('/:id', requireAuth, requireCsrf, deleteItem);

export default router;
