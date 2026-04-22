/**
 * HMAC-SHA256 Implementation from Scratch
 * Following RFC 2104 specification
 * Uses custom SHA-256 implementation
 */

import { sha256, sha256Bytes, stringToBytes } from './sha256.js';

const BLOCK_SIZE = 64; // SHA-256 block size in bytes

/**
 * Compute HMAC-SHA256
 * @param {string} key - The secret key
 * @param {string} message - The message to authenticate
 * @returns {string} Hex-encoded HMAC
 */
function hmac(key, message) {
  let keyBytes = stringToBytes(key);

  // If key is longer than block size, hash it
  if (keyBytes.length > BLOCK_SIZE) {
    keyBytes = sha256Bytes(key);
  }

  // Pad key to block size
  while (keyBytes.length < BLOCK_SIZE) {
    keyBytes.push(0x00);
  }

  // Create inner and outer padded keys
  const ipad = new Array(BLOCK_SIZE);
  const opad = new Array(BLOCK_SIZE);
  for (let i = 0; i < BLOCK_SIZE; i++) {
    ipad[i] = keyBytes[i] ^ 0x36;
    opad[i] = keyBytes[i] ^ 0x5c;
  }

  // Inner hash: SHA256(ipad || message)
  const innerMessage = [...ipad, ...stringToBytes(message)];
  const innerHash = sha256Bytes(innerMessage);

  // Outer hash: SHA256(opad || innerHash)
  const outerMessage = [...opad, ...innerHash];
  const result = sha256(outerMessage);

  return result;
}

/**
 * Constant-time comparison to prevent timing attacks
 * @param {string} a - First string
 * @param {string} b - Second string
 * @returns {boolean}
 */
function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

/**
 * Verify HMAC
 * @param {string} key - The secret key
 * @param {string} message - The message
 * @param {string} expectedMac - The expected HMAC hex string
 * @returns {boolean}
 */
function verifyHmac(key, message, expectedMac) {
  const computedMac = hmac(key, message);
  return constantTimeEqual(computedMac, expectedMac);
}

/**
 * Compute HMAC over multiple fields (concatenated with separator)
 * @param {string} key - The secret key
 * @param {Object} data - Object with field values
 * @param {string[]} fields - Array of field names to include
 * @returns {string} Hex-encoded HMAC
 */
function computeDataHmac(key, data, fields) {
  const message = fields.map(f => String(data[f] || '')).join('|');
  return hmac(key, message);
}

/**
 * Verify data integrity using HMAC
 * @param {string} key - The secret key
 * @param {Object} data - Object with field values
 * @param {string[]} fields - Array of field names to include
 * @param {string} storedHmac - The stored HMAC to verify against
 * @returns {boolean}
 */
function verifyDataHmac(key, data, fields, storedHmac) {
  const message = fields.map(f => String(data[f] || '')).join('|');
  return verifyHmac(key, message, storedHmac);
}

export { hmac, verifyHmac, computeDataHmac, verifyDataHmac };
