import express from 'express';
import { protect } from '../middleware/authMiddleware.js';
import { requireRole } from '../middleware/rbacMiddleware.js';
import { listKeys, keyStatus, rotateKeyEndpoint, revokeKeyEndpoint } from '../controllers/keyController.js';

const router = express.Router();

// All key management routes require admin role
router.get('/', protect, requireRole('admin'), listKeys);
router.get('/status', protect, requireRole('admin'), keyStatus);
router.post('/rotate/:keyId', protect, requireRole('admin'), rotateKeyEndpoint);
router.post('/revoke/:keyId', protect, requireRole('admin'), revokeKeyEndpoint);

export default router;
