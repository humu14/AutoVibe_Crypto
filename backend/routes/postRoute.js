import express from 'express';
import { protect } from '../middleware/authMiddleware.js';
import { requireRole } from '../middleware/rbacMiddleware.js';
import { createPost, getMyPosts, getPostById, updatePost, setPostVisibility, getAllPosts, getPublicPosts, deletePost } from '../controllers/postController.js';

const router = express.Router();

router.get('/public', getPublicPosts);
router.post('/', protect, createPost);
router.get('/my', protect, getMyPosts);
router.get('/admin/all', protect, requireRole('admin'), getAllPosts);
router.patch('/:id/visibility', protect, setPostVisibility);
router.get('/:id', protect, getPostById);
router.put('/:id', protect, updatePost);
router.delete('/:id', protect, deletePost);

export default router;
