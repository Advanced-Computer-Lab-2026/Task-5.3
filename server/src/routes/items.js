import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { csrfProtection } from '../middleware/csrf.js';
import { getAllItems, getItem, createItem, updateItem, deleteItem } from '../controllers/itemController.js';

const router = Router();

// Reading is public; writing requires a logged-in user.
router.get('/', getAllItems);
router.get('/:id', getItem);
router.post('/', requireAuth, csrfProtection, createItem);
router.patch('/:id', requireAuth, csrfProtection, updateItem);
router.delete('/:id', requireAuth, csrfProtection, deleteItem);

export default router;
