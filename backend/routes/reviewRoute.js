import express from 'express';
import {protect} from '../middleware/authMiddleware.js';
import { requireRole } from '../middleware/rbacMiddleware.js';
import { createReview, getReview, deleteReview, getAllReviews } from '../controllers/reviewController.js';

const router = express.Router();

router.post('/', protect, createReview);
router.delete('/', protect, requireRole('admin'), deleteReview);
router.get('/', protect, requireRole('admin'), getAllReviews);
router.get('/:id', getReview);


export default router;