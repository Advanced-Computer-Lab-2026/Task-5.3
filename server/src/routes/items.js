import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { doubleCsrfProtection } from '../middleware/csrf.js';
import { getAllItems, getItem, createItem, updateItem, deleteItem } from '../controllers/itemController.js';

const router = Router();

// Reading is public; writing requires a logged-in user.
router.get('/', getAllItems);
router.get('/:id', getItem);
router.post('/', requireAuth, doubleCsrfProtection, createItem);
router.patch('/:id', requireAuth, doubleCsrfProtection, updateItem);
router.delete('/:id', requireAuth, doubleCsrfProtection, deleteItem);

export default router;
