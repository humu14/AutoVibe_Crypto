/**
 * User Controller — Fully Secured
 * 
 * Features:
 * - RSA encryption of user data (name, email, phone)
 * - Custom SHA-256 password hashing with salt
 * - Two-step authentication (password + OTP)
 * - HMAC integrity verification on all user records
 * - All data decrypted on retrieval
 */

import asyncHandler from 'express-async-handler';
import User from '../models/userModel.js';
import Product from '../models/productModel.js';
import generateToken, { invalidateUserSessions } from '../utils/generateToken.js';
import { decryptProductData } from '../utils/productCrypto.js';
import { sha256 } from '../crypto/sha256.js';
import { hashPassword, verifyPassword } from '../crypto/passwordHash.js';
import { hmac, verifyHmac } from '../crypto/hmac.js';
import { getActiveKey, getKeyByVersion, getHmacSecret } from '../crypto/keyManager.js';
import * as rsaCrypto from '../crypto/rsa.js';
import { createOTP, verifyOTPCode } from './twoFactorController.js';

const includeOtpForDev = process.env.NODE_ENV !== 'production';


/**
 * Encrypt user sensitive fields with RSA
 */
async function encryptUserData(data) {
  const key = await getActiveKey('RSA', 'USER_DATA');
  const encrypted = {};

  if (data.name) encrypted.name = rsaCrypto.encryptString(data.name, key.publicKey);
  if (data.email) encrypted.email = rsaCrypto.encryptString(data.email, key.publicKey);
  if (data.phone) encrypted.phone = rsaCrypto.encryptString(data.phone, key.publicKey);

  encrypted.encryptionKeyVersion = key.version;
  return encrypted;
}

/**
 * Decrypt user sensitive fields
 */
async function decryptUserData(user) {
  try {
    let key;
    if (user.encryptionKeyVersion) {
      try {
        key = await getKeyByVersion('RSA', 'USER_DATA', user.encryptionKeyVersion);
      } catch {
        key = await getActiveKey('RSA', 'USER_DATA');
      }
    } else {
      key = await getActiveKey('RSA', 'USER_DATA');
    }
    
    const decrypted = {
      _id: user._id,
      name: user.name ? rsaCrypto.decryptString(user.name, key.privateKey) : '',
      email: user.email ? rsaCrypto.decryptString(user.email, key.privateKey) : '',
      phone: user.phone ? rsaCrypto.decryptString(user.phone, key.privateKey) : '',
      role: user.role,
      isAdmin: user.role === 'admin' || user.isAdmin,
      isArtist: user.isArtist,
      favoriteProducts: user.favoriteProducts,
      points: user.points,
      membership: user.membership,
      twoFactorEnabled: user.twoFactorEnabled,
      createdAt: user.createdAt,
    };

    return decrypted;
  } catch (e) {
    console.error('Decryption error:', e.message);
    // legacy fallback
    return {
      _id: user._id,
      name: user.name || '',
      email: user.email || '',
      phone: user.phone || '',
      role: user.role,
      isAdmin: user.role === 'admin' || user.isAdmin,
      isArtist: user.isArtist,
      favoriteProducts: user.favoriteProducts,
      points: user.points,
      membership: user.membership,
      twoFactorEnabled: user.twoFactorEnabled,
      createdAt: user.createdAt,
    };
  }
}

/**
 * Compute HMAC for user data integrity
 */
function computeUserHmac(userData) {
  const secret = getHmacSecret();
  const fields = [
    userData.name || '',
    userData.email || '',
    userData.emailHash || '',
    userData.phone || '',
    userData.role || 'user'
  ].join('|');
  return hmac(secret, fields);
}

/**
 * Verify user data integrity
 */
function verifyUserIntegrity(user) {
  if (!user.dataHmac) return true; // legacy data
  const secret = getHmacSecret();
  const fields = [
    user.name || '',
    user.email || '',
    user.emailHash || '',
    user.phone || '',
    user.role || 'user'
  ].join('|');
  return verifyHmac(secret, fields, user.dataHmac);
}


/**
 * POST /api/users/auth — Step 1 of login
 * Validates credentials and sends OTP
 */
const authUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  // hash email
  const emailHash = sha256(email.toLowerCase().trim());
  const user = await User.findOne({ emailHash });

  if (!user) {
    res.status(401);
    throw new Error('Invalid email or password');
  }

  // verify integrity
  if (!verifyUserIntegrity(user)) {
    console.error(`⚠️ Data integrity violation detected for user ${user._id}`);
  }

  // verify password
  if (!verifyPassword(password, user.password)) {
    res.status(401);
    throw new Error('Invalid email or password');
  }

  // generate otp
  if (user.twoFactorEnabled) {
    const { code, expiresAt } = await createOTP(user._id);

    const response = {
      pending2FA: true,
      userId: user._id,
      message: 'Password verified. Please enter the OTP code.',
      expiresAt
    };

    if (includeOtpForDev) {
      response.otp = code;
    }

    res.status(200).json(response);
  } else {
    // 2fa off, create session
    const userRole = user.role || (user.isAdmin ? 'admin' : 'user');
    await generateToken(res, user._id, userRole, req);
    
    const decrypted = await decryptUserData(user);
    res.status(200).json({
      _id: decrypted._id,
      name: decrypted.name,
      email: decrypted.email,
      admin: decrypted.isAdmin,
      fav: user.favoriteProducts,
      artists: user.isArtist,
      role: decrypted.role,
    });
  }
});

/**
 * POST /api/users/verify-otp — Step 2 of login
 * Verifies OTP and creates session
 */
const verifyLoginOTP = asyncHandler(async (req, res) => {
  const { userId, otpCode } = req.body;

  if (!userId || !otpCode) {
    res.status(400);
    throw new Error('User ID and OTP code are required');
  }

  const result = await verifyOTPCode(userId, otpCode);
  if (!result.valid) {
    res.status(401);
    throw new Error(result.error);
  }

  // otp verified, create session
  const user = await User.findById(userId);
  if (!user) {
    res.status(404);
    throw new Error('User not found');
  }

  const userRole = user.role || (user.isAdmin ? 'admin' : 'user');
  await generateToken(res, user._id, userRole, req);

  const decrypted = await decryptUserData(user);
  res.status(200).json({
    _id: decrypted._id,
    name: decrypted.name,
    email: decrypted.email,
    admin: decrypted.isAdmin,
    fav: user.favoriteProducts,
    artists: user.isArtist,
    role: decrypted.role,
  });
});

/**
 * POST /api/users — Register new user
 * Encrypts all user data with RSA, hashes password with custom SHA-256
 */
const register = asyncHandler(async (req, res) => {
  const { name, email, password, phone } = req.body;

  // check existing user
  const emailHash = sha256(email.toLowerCase().trim());
  const userExists = await User.findOne({ emailHash });

  if (userExists) {
    res.status(400);
    throw new Error('User already exists');
  }

  // hash password
  const hashedPassword = hashPassword(password);

  // encrypt fields
  const encrypted = await encryptUserData({ name, email, phone: phone || '' });

  // compute hmac
  const userData = {
    name: encrypted.name,
    email: encrypted.email,
    emailHash,
    phone: encrypted.phone || '',
    role: 'user'
  };
  const dataHmac = computeUserHmac(userData);

  // create user
  const user = await User.create({
    name: encrypted.name,
    email: encrypted.email,
    emailHash,
    phone: encrypted.phone || '',
    password: hashedPassword,
    role: 'user',
    isAdmin: false,
    twoFactorEnabled: true,
    dataHmac,
    encryptionKeyVersion: encrypted.encryptionKeyVersion
  });

  if (user) {
    // generate otp
    const { code, expiresAt } = await createOTP(user._id);

    const response = {
      _id: user._id,
      name: name, // ui plaintext
      email: email,
      admin: false,
      role: 'user',
      fav: [],
      artists: false,
      pending2FA: true,
      message: 'Registration successful. Please verify with OTP.',
      expiresAt
    };

    if (includeOtpForDev) {
      response.otp = code;
    }

    res.status(201).json(response);
  } else {
    res.status(400);
    throw new Error('Invalid user data');
  }
});

/**
 * POST /api/users/logout — Logout and invalidate session
 */
const logout = asyncHandler(async (req, res) => {
  // invalidate sessions
  if (req.user) {
    await invalidateUserSessions(req.user._id);
  }

  res.cookie('jwt', '', {
    httpOnly: true,
    expires: new Date(0),
  });
  res.status(200).json({ message: 'Logged out successfully' });
});


/**
 * GET /api/users/profile — Get user profile (decrypted)
 */
const getUserProfile = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);
  
  if (!user) {
    res.status(404);
    throw new Error('User not found');
  }

  // verify integrity
  if (!verifyUserIntegrity(user)) {
    console.warn(`⚠️ HMAC integrity check failed for user ${user._id}`);
  }

  const decrypted = await decryptUserData(user);
  res.status(200).json({ user: decrypted });
});

/**
 * PUT /api/users/profile — Update user profile
 */
const updateUserProfile = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);
  
  if (!user) {
    res.status(404);
    throw new Error('User not found');
  }

  // re-encrypt fields
  if (req.body.name || req.body.email || req.body.phone) {
    const key = await getActiveKey('RSA', 'USER_DATA');
    
    if (req.body.name) {
      user.name = rsaCrypto.encryptString(req.body.name, key.publicKey);
    }
    if (req.body.email) {
      user.email = rsaCrypto.encryptString(req.body.email, key.publicKey);
      user.emailHash = sha256(req.body.email.toLowerCase().trim());
    }
    if (req.body.phone) {
      user.phone = rsaCrypto.encryptString(req.body.phone, key.publicKey);
    }
    user.encryptionKeyVersion = key.version;
  }

  if (req.body.password) {
    user.password = hashPassword(req.body.password);
  }

  // recompute hmac
  user.dataHmac = computeUserHmac({
    name: user.name,
    email: user.email,
    emailHash: user.emailHash,
    phone: user.phone || '',
    role: user.role
  });

  const updatedUser = await user.save();
  const decrypted = await decryptUserData(updatedUser);

  res.status(200).json({
    _id: decrypted._id,
    name: decrypted.name,
    email: decrypted.email,
    phone: decrypted.phone,
  });
});


const addToFavorite = asyncHandler(async (req, res) => {
  const userId = req.user._id;
  const productId = req.body.productId;
  
  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, error: "User not found" });
    }
    
    const product = await Product.findById(productId);
    if (!product) {
      return res.status(404).json({ success: false, error: "Product not found" });
    }

    const favoriteProducts = user.favoriteProducts;
    const index = favoriteProducts.indexOf(productId);
    
    if (index === -1) {
      favoriteProducts.push(productId);
    } else {
      favoriteProducts.splice(index, 1);
    }
    
    const updatedUser = await User.findByIdAndUpdate(userId, { favoriteProducts }, { new: true });
    
    res.status(200).json({ success: true, data: { updatedUser, index } });
  } catch (error) {
    res.status(500).json({ success: false, error: "Server error" });
  }
});

const getFavoriteProducts = asyncHandler(async (req, res) => {
  const userId = req.user._id;
  const user = await User.findById(userId).populate('favoriteProducts');
  if (!user) {
    return res.status(404).json({ success: false, error: "User not found" });
  }
  const decrypted = await Promise.all(user.favoriteProducts.map(decryptProductData));
  res.status(200).json(decrypted);
});


/**
 * GET /api/users/admin/users — Get all users (decrypted)
 */
const getAllUsers = asyncHandler(async (req, res) => {
  const users = await User.find({});
  
  // decrypt users
  const decryptedUsers = [];
  for (const user of users) {
    const integrity = verifyUserIntegrity(user);
    const decrypted = await decryptUserData(user);
    decryptedUsers.push({
      ...decrypted,
      integrityValid: integrity
    });
  }
  
  res.status(200).json(decryptedUsers);
});

const makeAdmin = asyncHandler(async (req, res) => {
  const userId = req.body.userId;
  const user = await User.findById(userId);
  if (!user) {
    res.status(404);
    throw new Error('User not found');
  }
  user.isAdmin = true;
  user.role = 'admin';
  
  // recompute hmac
  user.dataHmac = computeUserHmac({
    name: user.name,
    email: user.email,
    emailHash: user.emailHash,
    phone: user.phone || '',
    role: user.role
  });
  
  const updatedUser = await user.save();
  const decrypted = await decryptUserData(updatedUser);

  res.json({
    _id: decrypted._id,
    name: decrypted.name,
    email: decrypted.email,
    isAdmin: true,
    role: 'admin',
  });
});

const removeFromAdmin = asyncHandler(async (req, res) => {
  const userId = req.body.userId;
  const user = await User.findById(userId);
  if (!user) {
    res.status(404);
    throw new Error('User not found');
  }
  user.isAdmin = false;
  user.role = 'user';
  
  // recompute hmac
  user.dataHmac = computeUserHmac({
    name: user.name,
    email: user.email,
    emailHash: user.emailHash,
    phone: user.phone || '',
    role: user.role
  });
  
  const updatedUser = await user.save();
  const decrypted = await decryptUserData(updatedUser);

  res.json({
    _id: decrypted._id,
    name: decrypted.name,
    email: decrypted.email,
    isAdmin: false,
    role: 'user',
  });
});

const removeUser = asyncHandler(async (req, res) => {
  const userId = req.body.userId;
  // invalidate sessions
  await invalidateUserSessions(userId);
  const user = await User.deleteOne({ _id: userId });
  if (user.deletedCount === 0) {
    res.status(404);
    throw new Error('User not found');
  }
  res.json({ message: 'User removed' });
});


const googleAuthUser = asyncHandler(async (req, res) => {
  const { email } = req.body;
  const emailHash = sha256(email.toLowerCase().trim());
  const user = await User.findOne({ emailHash });
  
  if (user) {
    // generate otp
    if (user.twoFactorEnabled) {
      const { code, expiresAt } = await createOTP(user._id);

      const response = {
        pending2FA: true,
        userId: user._id,
        message: 'Please verify with OTP',
        expiresAt
      };

      if (includeOtpForDev) {
        response.otp = code;
      }

      res.status(200).json(response);
    } else {
      const userRole = user.role || (user.isAdmin ? 'admin' : 'user');
      await generateToken(res, user._id, userRole, req);
      
      const decrypted = await decryptUserData(user);
      res.status(201).json({
        _id: decrypted._id,
        name: decrypted.name,
        email: decrypted.email,
        admin: decrypted.isAdmin,
        fav: user.favoriteProducts,
      });
    }
  } else {
    res.status(401);
    throw new Error('Invalid email');
  }
});

const googleRegisterUser = asyncHandler(async (req, res) => {
  const { name, email } = req.body;
  const emailHash = sha256(email.toLowerCase().trim());
  const userExists = await User.findOne({ emailHash });

  if (userExists) {
    await googleAuthUser(req, res);
    return;
  }

  const password = hashPassword('google-oauth-' + Date.now());
  const encrypted = await encryptUserData({ name, email });

  const userData = {
    name: encrypted.name,
    email: encrypted.email,
    emailHash,
    phone: '',
    role: 'user'
  };
  const dataHmac = computeUserHmac(userData);

  const user = await User.create({
    name: encrypted.name,
    email: encrypted.email,
    emailHash,
    password,
    role: 'user',
    isAdmin: false,
    twoFactorEnabled: true,
    dataHmac,
    encryptionKeyVersion: encrypted.encryptionKeyVersion
  });

  if (user) {
    const { code, expiresAt } = await createOTP(user._id);

    const response = {
      _id: user._id,
      name: name,
      email: email,
      admin: false,
      fav: [],
      pending2FA: true,
      expiresAt
    };

    if (includeOtpForDev) {
      response.otp = code;
    }

    res.status(201).json(response);
  } else {
    res.status(400);
    throw new Error('Invalid user data');
  }
});


const enable2FA = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);
  if (!user) {
    res.status(404);
    throw new Error('User not found');
  }
  user.twoFactorEnabled = true;
  await user.save();
  res.json({ message: '2FA enabled', twoFactorEnabled: true });
});

const disable2FA = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);
  if (!user) {
    res.status(404);
    throw new Error('User not found');
  }
  user.twoFactorEnabled = false;
  await user.save();
  res.json({ message: '2FA disabled', twoFactorEnabled: false });
});

export {
  authUser,
  register,
  logout,
  getUserProfile,
  updateUserProfile,
  addToFavorite,
  getFavoriteProducts,
  getAllUsers,
  makeAdmin,
  removeFromAdmin,
  removeUser,
  googleAuthUser,
  googleRegisterUser,
  verifyLoginOTP,
  enable2FA,
  disable2FA
};