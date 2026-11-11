import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { getAllItems, getItem, createItem, updateItem, deleteItem } from '../controllers/itemController.js';

const router = Router();

// Reading is public; writing requires a logged-in user.
router.get('/', getAllItems);
router.get('/:id', getItem);
router.post('/', requireAuth, createItem);
router.patch('/:id', requireAuth, updateItem);
router.delete('/:id', requireAuth, deleteItem);

export default router;
