/**
 * RSA Encryption Implementation from Scratch
 * Uses native JavaScript BigInt for large number arithmetic
 * No built-in crypto libraries used
 * 
 * Implements:
 * - Miller-Rabin primality testing
 * - Key generation (1024-bit default)
 * - Encryption/Decryption
 * - String encryption with chunking for long messages
 */

// ==================== MATH UTILITIES ====================

/**
 * Modular exponentiation: (base^exp) mod mod
 * Uses binary exponentiation (square-and-multiply)
 * @param {BigInt} base
 * @param {BigInt} exp
 * @param {BigInt} mod
 * @returns {BigInt}
 */
function modPow(base, exp, mod) {
  if (mod === 1n) return 0n;
  let result = 1n;
  base = ((base % mod) + mod) % mod;
  while (exp > 0n) {
    if (exp % 2n === 1n) {
      result = (result * base) % mod;
    }
    exp = exp >> 1n;
    base = (base * base) % mod;
  }
  return result;
}

/**
 * Greatest Common Divisor using Euclidean algorithm
 * @param {BigInt} a
 * @param {BigInt} b
 * @returns {BigInt}
 */
function gcd(a, b) {
  a = a < 0n ? -a : a;
  b = b < 0n ? -b : b;
  while (b > 0n) {
    [a, b] = [b, a % b];
  }
  return a;
}

/**
 * Extended Euclidean Algorithm
 * Returns [gcd, x, y] such that a*x + b*y = gcd(a, b)
 * @param {BigInt} a
 * @param {BigInt} b
 * @returns {BigInt[]}
 */
function extGcd(a, b) {
  if (a === 0n) return [b, 0n, 1n];
  const [g, x, y] = extGcd(b % a, a);
  return [g, y - (b / a) * x, x];
}

/**
 * Modular inverse: find x such that (a * x) ≡ 1 (mod m)
 * @param {BigInt} a
 * @param {BigInt} m
 * @returns {BigInt}
 */
function modInverse(a, m) {
  const [g, x] = extGcd(((a % m) + m) % m, m);
  if (g !== 1n) throw new Error('Modular inverse does not exist');
  return ((x % m) + m) % m;
}

/**
 * Generate a random BigInt with specified bit length
 * @param {number} bits
 * @returns {BigInt}
 */
function randomBigInt(bits) {
  const bytes = Math.ceil(bits / 8);
  let hex = '';
  for (let i = 0; i < bytes; i++) {
    const byte = Math.floor(Math.random() * 256);
    hex += byte.toString(16).padStart(2, '0');
  }
  let result = BigInt('0x' + hex);
  // Ensure the top bit is set (so we get exactly the right bit length)
  result = result | (1n << BigInt(bits - 1));
  // Ensure it's odd (for prime candidate)
  result = result | 1n;
  return result;
}

// ==================== PRIMALITY TESTING ====================

/**
 * Miller-Rabin primality test
 * @param {BigInt} n - Number to test
 * @param {number} rounds - Number of test rounds (higher = more accurate)
 * @returns {boolean} true if probably prime
 */
function millerRabin(n, rounds = 20) {
  if (n < 2n) return false;
  if (n === 2n || n === 3n) return true;
  if (n % 2n === 0n) return false;

  // Write n-1 as 2^r * d where d is odd
  let r = 0n;
  let d = n - 1n;
  while (d % 2n === 0n) {
    r++;
    d = d / 2n;
  }

  // Witness loop
  for (let i = 0; i < rounds; i++) {
    // Random base a in [2, n-2]
    const range = n - 4n;
    let a = 2n;
    if (range > 0n) {
      const randBits = n.toString(2).length;
      let candidate;
      do {
        candidate = randomBigInt(randBits) % range;
      } while (candidate < 0n);
      a = candidate + 2n;
    }

    let x = modPow(a, d, n);

    if (x === 1n || x === n - 1n) continue;

    let found = false;
    for (let j = 0n; j < r - 1n; j++) {
      x = modPow(x, 2n, n);
      if (x === n - 1n) {
        found = true;
        break;
      }
    }
    if (!found) return false;
  }

  return true;
}

/**
 * Generate a probable prime of specified bit length
 * @param {number} bits
 * @returns {BigInt}
 */
function generatePrime(bits) {
  let candidate;
  let attempts = 0;
  do {
    candidate = randomBigInt(bits);
    attempts++;
    if (attempts > 10000) {
      throw new Error('Failed to generate prime after 10000 attempts');
    }
  } while (!millerRabin(candidate, 20));
  return candidate;
}

// ==================== RSA KEY GENERATION ====================

/**
 * Generate RSA key pair
 * @param {number} bitLength - Key size in bits (default 1024)
 * @returns {Object} { publicKey: {n, e}, privateKey: {n, d, p, q} }
 */
function generateKeyPair(bitLength = 1024) {
  const halfBits = Math.floor(bitLength / 2);
  
  // Generate two distinct large primes
  const p = generatePrime(halfBits);
  let q;
  do {
    q = generatePrime(halfBits);
  } while (q === p);

  // Compute modulus
  const n = p * q;

  // Euler's totient
  const phi = (p - 1n) * (q - 1n);

  // Public exponent (commonly 65537)
  const e = 65537n;

  // Verify gcd(e, phi) = 1
  if (gcd(e, phi) !== 1n) {
    // Extremely unlikely with e=65537, but retry if it happens
    return generateKeyPair(bitLength);
  }

  // Private exponent
  const d = modInverse(e, phi);

  return {
    publicKey: {
      n: n.toString(16),
      e: e.toString(16)
    },
    privateKey: {
      n: n.toString(16),
      d: d.toString(16),
      p: p.toString(16),
      q: q.toString(16)
    }
  };
}

// ==================== ENCRYPTION / DECRYPTION ====================

/**
 * Encrypt a BigInt message with RSA public key
 * @param {BigInt} message - Message as BigInt (must be < n)
 * @param {Object} publicKey - {n: hex, e: hex}
 * @returns {string} Hex-encoded ciphertext
 */
function encrypt(message, publicKey) {
  const n = BigInt('0x' + publicKey.n);
  const e = BigInt('0x' + publicKey.e);
  
  if (message >= n) {
    throw new Error('Message too large for key size');
  }

  const ciphertext = modPow(message, e, n);
  return ciphertext.toString(16);
}

/**
 * Decrypt a ciphertext with RSA private key
 * @param {string} ciphertextHex - Hex-encoded ciphertext
 * @param {Object} privateKey - {n: hex, d: hex}
 * @returns {BigInt} Decrypted message as BigInt
 */
function decrypt(ciphertextHex, privateKey) {
  const n = BigInt('0x' + privateKey.n);
  const d = BigInt('0x' + privateKey.d);
  const ciphertext = BigInt('0x' + ciphertextHex);

  return modPow(ciphertext, d, n);
}

// ==================== STRING ENCRYPTION ====================

/**
 * Convert a string to a BigInt
 * @param {string} str
 * @returns {BigInt}
 */
function stringToBigInt(str) {
  let hex = '';
  for (let i = 0; i < str.length; i++) {
    hex += str.charCodeAt(i).toString(16).padStart(4, '0');
  }
  return hex.length > 0 ? BigInt('0x' + hex) : 0n;
}

/**
 * Convert a BigInt back to string
 * @param {BigInt} bigint
 * @returns {string}
 */
function bigIntToString(bigint) {
  if (bigint === 0n) return '';
  let hex = bigint.toString(16);
  // Pad to even length
  if (hex.length % 4 !== 0) {
    hex = hex.padStart(Math.ceil(hex.length / 4) * 4, '0');
  }
  let result = '';
  for (let i = 0; i < hex.length; i += 4) {
    const charCode = parseInt(hex.substr(i, 4), 16);
    if (charCode > 0) {
      result += String.fromCharCode(charCode);
    }
  }
  return result;
}

/**
 * Calculate maximum chunk size for a given key
 * @param {Object} publicKey - {n: hex, e: hex}
 * @returns {number} Maximum characters per chunk
 */
function getMaxChunkSize(publicKey) {
  const n = BigInt('0x' + publicKey.n);
  const nBits = n.toString(2).length;
  // Each character takes 4 hex digits = 16 bits
  // Leave some room for safety (use 80% of key size)
  return Math.floor((nBits * 0.8) / 16);
}

/**
 * Encrypt a string with RSA, automatically chunking if needed
 * @param {string} plaintext - String to encrypt
 * @param {Object} publicKey - {n: hex, e: hex}
 * @returns {string} JSON string of encrypted chunks
 */
function encryptString(plaintext, publicKey) {
  if (!plaintext || plaintext.length === 0) return '';
  
  const maxChunkSize = getMaxChunkSize(publicKey);
  const chunks = [];

  for (let i = 0; i < plaintext.length; i += maxChunkSize) {
    const chunk = plaintext.substring(i, i + maxChunkSize);
    const bigIntMsg = stringToBigInt(chunk);
    const encrypted = encrypt(bigIntMsg, publicKey);
    chunks.push(encrypted);
  }

  return JSON.stringify(chunks);
}

/**
 * Decrypt a string encrypted with encryptString
 * @param {string} ciphertext - JSON string of encrypted chunks
 * @param {Object} privateKey - {n: hex, d: hex}
 * @returns {string} Decrypted plaintext
 */
function decryptString(ciphertext, privateKey) {
  if (!ciphertext || ciphertext.length === 0) return '';
  
  try {
    const chunks = JSON.parse(ciphertext);
    let plaintext = '';

    for (const chunk of chunks) {
      const decryptedBigInt = decrypt(chunk, privateKey);
      plaintext += bigIntToString(decryptedBigInt);
    }

    return plaintext;
  } catch (e) {
    // If it's not valid JSON, it might be unencrypted legacy data
    // console.error('RSA decryption failed:', e.message);
    return ciphertext;
  }
}

// Sign/verify functions that take sha256 as parameter to avoid circular imports
/**
 * Sign data with RSA private key (synchronous version)
 * @param {string} data - Data to sign
 * @param {Object} privateKey - {n: hex, d: hex}
 * @param {Function} sha256Fn - SHA-256 hash function
 * @returns {string} Hex-encoded signature
 */
function signSync(data, privateKey, sha256Fn) {
  const hash = sha256Fn(data);
  const hashBigInt = BigInt('0x' + hash);
  const n = BigInt('0x' + privateKey.n);
  const reducedHash = hashBigInt % n;
  const d = BigInt('0x' + privateKey.d);
  const signature = modPow(reducedHash, d, n);
  return signature.toString(16);
}

/**
 * Verify RSA signature (synchronous version)
 * @param {string} data - Original data
 * @param {string} signatureHex - Hex-encoded signature
 * @param {Object} publicKey - {n: hex, e: hex}
 * @param {Function} sha256Fn - SHA-256 hash function
 * @returns {boolean}
 */
function verifySync(data, signatureHex, publicKey, sha256Fn) {
  const hash = sha256Fn(data);
  const hashBigInt = BigInt('0x' + hash);
  const n = BigInt('0x' + publicKey.n);
  const reducedHash = hashBigInt % n;
  
  const signature = BigInt('0x' + signatureHex);
  const e = BigInt('0x' + publicKey.e);
  const decrypted = modPow(signature, e, n);
  
  return decrypted === reducedHash;
}

/**
 * Serialize key to JSON-safe format
 */
function serializeKey(key) {
  return JSON.parse(JSON.stringify(key));
}

/**
 * Deserialize key from stored format
 */
function deserializeKey(keyData) {
  return keyData;
}

export {
  generateKeyPair,
  encrypt,
  decrypt,
  encryptString,
  decryptString,
  signSync as sign,
  verifySync as verify,
  serializeKey,
  deserializeKey,
  modPow,
  gcd,
  modInverse,
  millerRabin,
  generatePrime
};
