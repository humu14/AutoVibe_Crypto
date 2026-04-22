/**
 * Key Management Controller
 * Admin-only endpoints for encryption key lifecycle management
 */

import asyncHandler from 'express-async-handler';
import { getAllKeys, getKeyStatus, rotateKey, revokeKey } from '../crypto/keyManager.js';

/**
 * GET /api/keys — List all encryption keys
 */
const listKeys = asyncHandler(async (req, res) => {
  const keys = await getAllKeys();
  res.status(200).json(keys);
});

/**
 * GET /api/keys/status — Key health dashboard
 */
const keyStatus = asyncHandler(async (req, res) => {
  const status = await getKeyStatus();
  res.status(200).json(status);
});

/**
 * POST /api/keys/rotate/:keyId — Rotate an encryption key
 */
const rotateKeyEndpoint = asyncHandler(async (req, res) => {
  const { keyId } = req.params;

  if (!keyId) {
    res.status(400);
    throw new Error('Key ID is required');
  }

  const result = await rotateKey(keyId);
  res.status(200).json({
    message: 'Key rotated successfully',
    ...result
  });
});

/**
 * POST /api/keys/revoke/:keyId — Revoke an encryption key
 */
const revokeKeyEndpoint = asyncHandler(async (req, res) => {
  const { keyId } = req.params;

  if (!keyId) {
    res.status(400);
    throw new Error('Key ID is required');
  }

  const result = await revokeKey(keyId);
  res.status(200).json({
    message: 'Key revoked successfully',
    ...result
  });
});

export { listKeys, keyStatus, rotateKeyEndpoint, revokeKeyEndpoint };
