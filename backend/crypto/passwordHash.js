/**
 * Password Hashing with Salt — From Scratch
 * Uses iterative SHA-256 (PBKDF-style)
 * No built-in crypto hashing libraries
 */

import { sha256 } from './sha256.js';

/**
 * Generate a random salt string
 * Uses a combination of Math.random and Date.now for entropy
 * @param {number} length - Salt length in hex characters (default 32 = 16 bytes)
 * @returns {string} Hex-encoded salt
 */
function generateSalt(length = 32) {
  let salt = '';
  const chars = '0123456789abcdef';
  // Combine multiple entropy sources
  for (let i = 0; i < length; i++) {
    // Mix Math.random with time-based entropy
    const entropy = Math.random() * 0xffff + Date.now() + i;
    const idx = Math.floor(entropy) % 16;
    salt += chars[idx];
  }
  // Hash the salt itself once for better distribution
  return sha256(salt + Date.now().toString()).substring(0, length);
}

/**
 * Hash a password with salt using iterative SHA-256
 * @param {string} password - The plaintext password
 * @param {string} salt - The salt value
 * @param {number} iterations - Number of hash iterations (default 10000)
 * @returns {string} Hex-encoded hash
 */
function hashWithSalt(password, salt, iterations = 10000) {
  let hash = sha256(password + salt);
  for (let i = 1; i < iterations; i++) {
    hash = sha256(hash + salt + i.toString());
  }
  return hash;
}

/**
 * Hash a password (generate salt + compute hash)
 * @param {string} password - The plaintext password
 * @param {number} iterations - Number of iterations
 * @returns {string} Formatted hash string: $iterations$salt$hash
 */
function hashPassword(password, iterations = 10000) {
  const salt = generateSalt(32);
  const hash = hashWithSalt(password, salt, iterations);
  return `$${iterations}$${salt}$${hash}`;
}

/**
 * Verify a password against a stored hash
 * @param {string} password - The plaintext password to verify
 * @param {string} storedHash - The stored hash string ($iterations$salt$hash)
 * @returns {boolean} True if password matches
 */
function verifyPassword(password, storedHash) {
  try {
    const parts = storedHash.split('$');
    // Format: $iterations$salt$hash → ['', iterations, salt, hash]
    if (parts.length !== 4) return false;
    
    const iterations = parseInt(parts[1], 10);
    const salt = parts[2];
    const hash = parts[3];

    const computedHash = hashWithSalt(password, salt, iterations);
    
    // Constant-time comparison
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
