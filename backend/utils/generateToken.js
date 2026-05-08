/**
 * custom token generation
 */

import Session from '../models/sessionModel.js';
import { sha256 } from '../crypto/sha256.js';
import { getActiveKey } from '../crypto/keyManager.js';
import * as rsa from '../crypto/rsa.js';

/** encode string to base64url */
function base64urlEncode(str) {
  return Buffer.from(str, 'utf-8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/** compute session fingerprint */
function computeFingerprint(req) {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const userAgent = req.headers['user-agent'] || 'unknown';
  return sha256(ip + '|' + userAgent);
}

/** create a signed token and session */
const generateToken = async (res, userId, role, req) => {
  try {
    // get signing key
    const signingKey = await getActiveKey('RSA', 'SESSION_SIGNING');

    // create session
    const fingerprint = computeFingerprint(req);
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24h

    const session = new Session({
      userId,
      fingerprint,
      ipAddress: req.ip || req.connection.remoteAddress || 'unknown',
      userAgent: req.headers['user-agent'] || 'unknown',
      isValid: true,
      expiresAt
    });

    // build token
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

    // sign token
    const signature = rsa.sign(dataToSign, signingKey.privateKey, sha256);
    const token = `${dataToSign}.${signature}`;

    // store token hash
    session.token = sha256(token); // hash only
    await session.save();

    // set cookie
    res.cookie('jwt', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000, // 24h
    });

    return token;
  } catch (error) {
    console.error('Token generation error:', error);
    throw new Error('Failed to generate authentication token');
  }
};

/** invalidate user sessions */
const invalidateUserSessions = async (userId) => {
  await Session.updateMany(
    { userId, isValid: true },
    { isValid: false }
  );
};

/** clean expired sessions */
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