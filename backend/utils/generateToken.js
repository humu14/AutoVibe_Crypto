/**
 * Custom Token Generation — RSA-Signed Session Tokens
 * Replaces jsonwebtoken with custom implementation
 * Creates RSA-signed tokens and manages sessions
 */

import Session from '../models/sessionModel.js';
import { sha256 } from '../crypto/sha256.js';
import { getActiveKey } from '../crypto/keyManager.js';
import * as rsa from '../crypto/rsa.js';

/**
 * Encode string to base64url
 */
function base64urlEncode(str) {
  return Buffer.from(str, 'utf-8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Compute session fingerprint from request
 */
function computeFingerprint(req) {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const userAgent = req.headers['user-agent'] || 'unknown';
  return sha256(ip + '|' + userAgent);
}

/**
 * Generate a custom RSA-signed token and create a session
 * @param {Object} res - Express response object
 * @param {string} userId - User's MongoDB ID
 * @param {string} role - User's role ('admin' or 'user')
 * @param {Object} req - Express request object (for fingerprint)
 */
const generateToken = async (res, userId, role, req) => {
  try {
    // Get the signing key
    const signingKey = await getActiveKey('RSA', 'SESSION_SIGNING');

    // Create session record
    const fingerprint = computeFingerprint(req);
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    const session = new Session({
      userId,
      fingerprint,
      ipAddress: req.ip || req.connection.remoteAddress || 'unknown',
      userAgent: req.headers['user-agent'] || 'unknown',
      isValid: true,
      expiresAt
    });

    // Build token: header.payload.signature
    const header = {
      alg: 'RSA',
      typ: 'TOKEN'
    };

    const payload = {
      userId: userId.toString(),
      role,
      sessionId: session._id.toString(),
      iat: Date.now(),
      exp: expiresAt.getTime()
    };

    const headerB64 = base64urlEncode(JSON.stringify(header));
    const payloadB64 = base64urlEncode(JSON.stringify(payload));
    const dataToSign = `${headerB64}.${payloadB64}`;

    // Sign with RSA private key
    const signature = rsa.sign(dataToSign, signingKey.privateKey, sha256);
    const token = `${dataToSign}.${signature}`;

    // Update session with token
    session.token = sha256(token); // Store hash of token, not token itself
    await session.save();

    // Set cookie
    res.cookie('jwt', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    });

    return token;
  } catch (error) {
    console.error('Token generation error:', error);
    throw new Error('Failed to generate authentication token');
  }
};

/**
 * Invalidate all sessions for a user (for logout)
 * @param {string} userId
 */
const invalidateUserSessions = async (userId) => {
  await Session.updateMany(
    { userId, isValid: true },
    { isValid: false }
  );
};

/**
 * Clean up expired sessions
 */
const cleanupExpiredSessions = async () => {
  const result = await Session.deleteMany({
    $or: [
      { expiresAt: { $lt: new Date() } },
      { isValid: false, updatedAt: { $lt: new Date(Date.now() - 24 * 60 * 60 * 1000) } }
    ]
  });
  if (result.deletedCount > 0) {
    console.log(`🧹 Cleaned up ${result.deletedCount} expired sessions`);
  }
};

export default generateToken;
export { invalidateUserSessions, cleanupExpiredSessions };