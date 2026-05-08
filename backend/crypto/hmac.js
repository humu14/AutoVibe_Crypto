/** hmac-sha256 */

import { sha256, sha256Bytes, stringToBytes } from './sha256.js';

const BLOCK_SIZE = 64; // sha-256 block size

/** compute hmac */
function hmac(key, message) {
  let keyBytes = stringToBytes(key);

  // hash long key
  if (keyBytes.length > BLOCK_SIZE) {
    keyBytes = sha256Bytes(key);
  }

  // pad key
  while (keyBytes.length < BLOCK_SIZE) {
    keyBytes.push(0x00);
  }

  // build pads
  const ipad = new Array(BLOCK_SIZE);
  const opad = new Array(BLOCK_SIZE);
  for (let i = 0; i < BLOCK_SIZE; i++) {
    ipad[i] = keyBytes[i] ^ 0x36;
    opad[i] = keyBytes[i] ^ 0x5c;
  }

  // inner hash
  const innerMessage = [...ipad, ...stringToBytes(message)];
  const innerHash = sha256Bytes(innerMessage);

  // outer hash
  const outerMessage = [...opad, ...innerHash];
  const result = sha256(outerMessage);

  return result;
}

/** constant-time compare */
function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

/** verify hmac */
function verifyHmac(key, message, expectedMac) {
  const computedMac = hmac(key, message);
  return constantTimeEqual(computedMac, expectedMac);
}

/** compute data hmac */
function computeDataHmac(key, data, fields) {
  const message = fields.map(f => String(data[f] || '')).join('|');
  return hmac(key, message);
}

/** verify data hmac */
function verifyDataHmac(key, data, fields, storedHmac) {
  const message = fields.map(f => String(data[f] || '')).join('|');
  return verifyHmac(key, message, storedHmac);
}

export { hmac, verifyHmac, computeDataHmac, verifyDataHmac };
