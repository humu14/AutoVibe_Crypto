/** auth middleware */

import asyncHandler from 'express-async-handler';
import User from '../models/userModel.js';
import Session from '../models/sessionModel.js';
import { sha256 } from '../crypto/sha256.js';
import { getActiveKey } from '../crypto/keyManager.js';
import * as rsa from '../crypto/rsa.js';

/** fingerprint */
function computeFingerprint(req) {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const userAgent = req.headers['user-agent'] || 'unknown';
  return sha256(ip + '|' + userAgent);
}

/** decode base64url */
function base64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64').toString('utf-8');
}

/** protect routes */
const protect = asyncHandler(async (req, res, next) => {
  const token = req.cookies.jwt;

  if (!token) {
    res.status(401);
    throw new Error('Not authorized, no token');
  }

  try {
    // parse token
    const parts = token.split('.');
    if (parts.length !== 3) {
      res.status(401);
      throw new Error('Invalid token format');
    }

    const [headerB64, payloadB64, signatureHex] = parts;
    
    // decode payload
    const payload = JSON.parse(base64urlDecode(payloadB64));

    // check expiry
    if (payload.exp && Date.now() > payload.exp) {
      // invalidate session
      if (payload.sessionId) {
        await Session.findByIdAndUpdate(payload.sessionId, { isValid: false });
      }
      res.status(401);
      throw new Error('Token expired');
    }

    // verify signature
    const signingKey = await getActiveKey('RSA', 'SESSION_SIGNING');
    const dataToVerify = `${headerB64}.${payloadB64}`;
    const isValid = rsa.verify(dataToVerify, signatureHex, signingKey.publicKey, sha256);

    if (!isValid) {
      // try old keys
      let verified = false;
      try {
        const { getKeyByVersion } = await import('../crypto/keyManager.js');
        for (let v = signingKey.version - 1; v >= 1 && !verified; v--) {
          try {
            const oldKey = await getKeyByVersion('RSA', 'SESSION_SIGNING', v);
            verified = rsa.verify(dataToVerify, signatureHex, oldKey.publicKey, sha256);
          } catch (e) {
            // missing key version
          }
        }
      } catch (e) {
        // old key check failed
      }

      if (!verified) {
        res.status(401);
        throw new Error('Invalid token signature');
      }
    }

    // validate session
    if (payload.sessionId) {
      const session = await Session.findById(payload.sessionId);
      if (!session || !session.isValid) {
        res.status(401);
        throw new Error('Session invalid or expired');
      }

      // check fingerprint
      const currentFingerprint = computeFingerprint(req);
      if (session.fingerprint !== currentFingerprint) {
        session.isValid = false;
        await session.save();
        res.status(401);
        throw new Error('Session fingerprint mismatch. Session invalidated.');
      }

      // update last activity
      session.lastActivity = new Date();
      await session.save();
    }

    // attach user
    req.user = await User.findById(payload.userId).select('-password');
    if (!req.user) {
      res.status(401);
      throw new Error('User not found');
    }

    next();
  } catch (error) {
    if (!res.headersSent) {
      res.status(401);
      throw new Error(error.message || 'Not authorized, token failed');
    }
  }
});

/** admin middleware */
const admin = (req, res, next) => {
  if (req.user && (req.user.role === 'admin' || req.user.isAdmin)) {
    next();
  } else {
    res.status(403);
    throw new Error('Not authorized as an admin');
  }
};

export { protect, admin, computeFingerprint };