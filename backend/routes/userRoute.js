import express from 'express';
import { protect } from '../middleware/authMiddleware.js';
import { requireRole } from '../middleware/rbacMiddleware.js';
import {
  authUser, register, logout, getUserProfile, updateUserProfile,
  addToFavorite, getFavoriteProducts,
  getAllUsers, makeAdmin, removeFromAdmin, removeUser, 
  googleAuthUser, googleRegisterUser,
  verifyLoginOTP, enable2FA, disable2FA
} from '../controllers/userController.js';
import { resendOTP } from '../controllers/twoFactorController.js';

const router = express.Router();

// Public routes
router.post('/', register);
router.post('/auth', authUser);
router.post('/verify-otp', verifyLoginOTP);
router.post('/resend-otp', resendOTP);
router.post('/logout', logout);
router.post('/googlelogin', googleAuthUser);
router.post('/googleregister', googleRegisterUser);

// Protected routes (any authenticated user)
router.get('/profile', protect, getUserProfile);
router.put('/profile', protect, updateUserProfile);
router.put('/my/favorite', protect, addToFavorite);
router.get('/favorite', protect, getFavoriteProducts);
router.post('/enable-2fa', protect, enable2FA);
router.post('/disable-2fa', protect, disable2FA);

// Admin-only routes (RBAC enforced)
router.get('/admin/users', protect, requireRole('admin'), getAllUsers);
router.put('/admin/makeadmin', protect, requireRole('admin'), makeAdmin);
router.put('/admin/removeadmin', protect, requireRole('admin'), removeFromAdmin);
router.delete('/admin/removeuser', protect, requireRole('admin'), removeUser);

export default router;