/** password hash */

import { sha256 } from './sha256.js';

/** generate salt */
function generateSalt(length = 32) {
  let salt = '';
  const chars = '0123456789abcdef';
  // mix entropy
  for (let i = 0; i < length; i++) {
    // mix time entropy
    const entropy = Math.random() * 0xffff + Date.now() + i;
    const idx = Math.floor(entropy) % 16;
    salt += chars[idx];
  }
  // hash salt once
  return sha256(salt + Date.now().toString()).substring(0, length);
}

/** hash with salt */
function hashWithSalt(password, salt, iterations = 10000) {
  let hash = sha256(password + salt);
  for (let i = 1; i < iterations; i++) {
    hash = sha256(hash + salt + i.toString());
  }
  return hash;
}

/** hash password */
function hashPassword(password, iterations = 10000) {
  const salt = generateSalt(32);
  const hash = hashWithSalt(password, salt, iterations);
  return `$${iterations}$${salt}$${hash}`;
}

/** verify password */
function verifyPassword(password, storedHash) {
  try {
    const parts = storedHash.split('$');
    // parse stored hash
    if (parts.length !== 4) return false;
    
    const iterations = parseInt(parts[1], 10);
    const salt = parts[2];
    const hash = parts[3];

    const computedHash = hashWithSalt(password, salt, iterations);
    
    // constant-time compare
    if (computedHash.length !== hash.length) return false;
    let result = 0;
    for (let i = 0; i < computedHash.length; i++) {
      result |= computedHash.charCodeAt(i) ^ hash.charCodeAt(i);
    }
    return result === 0;
  } catch (e) {
    return false;
  }
}

export { generateSalt, hashPassword, verifyPassword };
