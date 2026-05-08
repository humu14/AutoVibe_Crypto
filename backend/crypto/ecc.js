/**
 * Elliptic Curve Cryptography (ECC) Implementation from Scratch
 * Implements EC-ElGamal encryption using the secp256k1 curve
 * No built-in crypto libraries used
 * 
 * Curve: secp256k1 (y² = x³ + 7 over F_p)
 * Used by Bitcoin — well-documented parameters
 */


const CURVE = {
  // field prime
  p: BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F'),
  // curve coeffs
  a: 0n,
  b: 7n,
  // generator
  Gx: BigInt('0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798'),
  Gy: BigInt('0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8'),
  // group order
  n: BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'),
  // cofactor
  h: 1n
};

// point at infinity
const POINT_INFINITY = { x: null, y: null };


/**
 * Modular addition
 */
function modAdd(a, b, p) {
  return ((a % p + b % p) % p + p) % p;
}

/**
 * Modular subtraction
 */
function modSub(a, b, p) {
  return ((a % p - b % p) % p + p) % p;
}

/**
 * Modular multiplication
 */
function modMul(a, b, p) {
  return ((a % p) * (b % p) % p + p) % p;
}

/**
 * Modular exponentiation using binary method
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
 * Modular inverse using Fermat's little theorem (p is prime)
 * a^(-1) ≡ a^(p-2) mod p
 */
function modInverse(a, p) {
  a = ((a % p) + p) % p;
  if (a === 0n) throw new Error('Cannot compute inverse of zero');
  return modPow(a, p - 2n, p);
}


/**
 * Check if a point is the point at infinity
 */
function isInfinity(P) {
  return P.x === null && P.y === null;
}

/**
 * Check if a point is on the curve
 */
function isOnCurve(P) {
  if (isInfinity(P)) return true;
  const { x, y } = P;
  const left = modPow(y, 2n, CURVE.p);
  const right = modAdd(modAdd(modPow(x, 3n, CURVE.p), modMul(CURVE.a, x, CURVE.p), CURVE.p), CURVE.b, CURVE.p);
  return left === right;
}

/**
 * Point addition: P + Q
 * @param {Object} P - Point {x, y}
 * @param {Object} Q - Point {x, y}
 * @returns {Object} Result point
 */
function pointAdd(P, Q) {
  if (isInfinity(P)) return Q;
  if (isInfinity(Q)) return P;

  const { p } = CURVE;

  // opposite points
  if (P.x === Q.x && modAdd(P.y, Q.y, p) === 0n) {
    return POINT_INFINITY;
  }

  let lambda;
  if (P.x === Q.x && P.y === Q.y) {
    // doubling
    lambda = modMul(
      modAdd(modMul(3n, modMul(P.x, P.x, p), p), CURVE.a, p),
      modInverse(modMul(2n, P.y, p), p),
      p
    );
  } else {
    // addition
    lambda = modMul(
      modSub(Q.y, P.y, p),
      modInverse(modSub(Q.x, P.x, p), p),
      p
    );
  }

  const x = modSub(modSub(modMul(lambda, lambda, p), P.x, p), Q.x, p);
  const y = modSub(modMul(lambda, modSub(P.x, x, p), p), P.y, p);

  return { x, y };
}

/**
 * Point doubling: 2P
 */
function pointDouble(P) {
  return pointAdd(P, P);
}

/**
 * Scalar multiplication: k * P using double-and-add
 * @param {BigInt} k - Scalar
 * @param {Object} P - Point {x, y}
 * @returns {Object} Result point
 */
function scalarMultiply(k, P) {
  if (k === 0n || isInfinity(P)) return POINT_INFINITY;
  if (k < 0n) {
    k = -k;
    P = { x: P.x, y: modSub(0n, P.y, CURVE.p) };
  }

  let result = POINT_INFINITY;
  let addend = { x: P.x, y: P.y };

  while (k > 0n) {
    if (k & 1n) {
      result = pointAdd(result, addend);
    }
    addend = pointDouble(addend);
    k >>= 1n;
  }

  return result;
}

/**
 * Negate a point: -P
 */
function pointNegate(P) {
  if (isInfinity(P)) return POINT_INFINITY;
  return { x: P.x, y: modSub(0n, P.y, CURVE.p) };
}


/**
 * Generate random BigInt in range [1, max-1]
 */
function randomScalar(max) {
  const bits = max.toString(2).length;
  const bytes = Math.ceil(bits / 8);
  let result;
  do {
    let hex = '';
    for (let i = 0; i < bytes; i++) {
      hex += Math.floor(Math.random() * 256).toString(16).padStart(2, '0');
    }
    result = BigInt('0x' + hex) % max;
  } while (result === 0n);
  return result;
}

/**
 * Generate ECC key pair
 * @returns {Object} { privateKey: hex string, publicKey: {x: hex, y: hex} }
 */
function generateKeyPair() {
  const G = { x: CURVE.Gx, y: CURVE.Gy };
  
  // private key
  const privateKey = randomScalar(CURVE.n);
  
  // public key
  const publicKey = scalarMultiply(privateKey, G);

  return {
    privateKey: privateKey.toString(16),
    publicKey: {
      x: publicKey.x.toString(16),
      y: publicKey.y.toString(16)
    }
  };
}


/**
 * Encode a message (bytes) to a curve point using Koblitz method
 * Maps an integer m to a point on the curve
 * @param {BigInt} m - Message as BigInt (must be small enough)
 * @returns {Object} Point {x, y} or null if encoding fails
 */
function encodeToPoint(m) {
  const { p, a, b } = CURVE;
  const k = 100n; // koblitz window
  
  for (let j = 0n; j < k; j++) {
    const x = modAdd(modMul(m, k, p), j, p);
    // curve equation
    const rhs = modAdd(modAdd(modPow(x, 3n, p), modMul(a, x, p), p), b, p);
    // check residue
    const euler = modPow(rhs, (p - 1n) / 2n, p);
    if (euler === 1n) {
      // sqrt for p % 4 == 3
      const y = modPow(rhs, (p + 1n) / 4n, p);
      return { x, y, j }; // decode offset
    }
  }
  throw new Error('Failed to encode message to curve point');
}

/**
 * Decode a curve point back to message
 * @param {Object} point - Point {x, y}
 * @returns {BigInt} Original message
 */
function decodeFromPoint(point) {
  const k = 100n;
  return point.x / k;
}

/**
 * EC-ElGamal Encrypt a BigInt value
 * @param {BigInt} message - Message value (must be small enough for encoding)
 * @param {Object} recipientPubKey - {x: hex, y: hex}
 * @returns {Object} {C1: {x,y}, C2: {x,y}} - Ciphertext pair
 */
function encryptValue(message, recipientPubKey) {
  const G = { x: CURVE.Gx, y: CURVE.Gy };
  const pubKey = {
    x: BigInt('0x' + recipientPubKey.x),
    y: BigInt('0x' + recipientPubKey.y)
  };

  // encode message
  const M = encodeToPoint(message);

  // ephemeral key
  const r = randomScalar(CURVE.n);

  // c1 = r * g
  const C1 = scalarMultiply(r, G);

  // shared secret
  const S = scalarMultiply(r, pubKey);

  // c2 = m + s
  const C2 = pointAdd({ x: M.x, y: M.y }, S);

  return {
    C1: { x: C1.x.toString(16), y: C1.y.toString(16) },
    C2: { x: C2.x.toString(16), y: C2.y.toString(16) }
  };
}

/**
 * EC-ElGamal Decrypt
 * @param {Object} ciphertext - {C1: {x,y hex}, C2: {x,y hex}}
 * @param {string} privateKeyHex - Private key as hex
 * @returns {BigInt} Decrypted message value
 */
function decryptValue(ciphertext, privateKeyHex) {
  const privKey = BigInt('0x' + privateKeyHex);

  const C1 = {
    x: BigInt('0x' + ciphertext.C1.x),
    y: BigInt('0x' + ciphertext.C1.y)
  };
  const C2 = {
    x: BigInt('0x' + ciphertext.C2.x),
    y: BigInt('0x' + ciphertext.C2.y)
  };

  // s = priv * c1
  const S = scalarMultiply(privKey, C1);

  // subtract shared secret
  const M = pointAdd(C2, pointNegate(S));

  // decode message
  return decodeFromPoint(M);
}


/**
 * Convert a short string to BigInt (max ~30 chars for secp256k1 with Koblitz k=100)
 */
function stringToBigInt(str) {
  let hex = '';
  for (let i = 0; i < str.length; i++) {
    hex += str.charCodeAt(i).toString(16).padStart(4, '0');
  }
  return hex.length > 0 ? BigInt('0x' + hex) : 0n;
}

/**
 * Convert BigInt back to string
 */
function bigIntToString(bigint) {
  if (bigint === 0n) return '';
  let hex = bigint.toString(16);
  if (hex.length % 4 !== 0) {
    hex = hex.padStart(Math.ceil(hex.length / 4) * 4, '0');
  }
  let result = '';
  for (let i = 0; i < hex.length; i += 4) {
    const charCode = parseInt(hex.substr(i, 4), 16);
    if (charCode > 0) result += String.fromCharCode(charCode);
  }
  return result;
}

/**
 * Maximum characters per chunk for EC-ElGamal
 * Limited by Koblitz encoding: message * k < p
 * With k=100, max message ≈ p/100, which is huge
 * But for practical purposes, we limit chunk size
 */
const MAX_CHUNK_CHARS = 15; // Conservative limit for safe encoding

/**
 * Encrypt a string using EC-ElGamal with chunking
 * @param {string} plaintext - String to encrypt
 * @param {Object} publicKey - {x: hex, y: hex}
 * @returns {string} JSON string of encrypted chunks
 */
function encryptString(plaintext, publicKey) {
  if (!plaintext || plaintext.length === 0) return '';

  const chunks = [];
  for (let i = 0; i < plaintext.length; i += MAX_CHUNK_CHARS) {
    const chunk = plaintext.substring(i, i + MAX_CHUNK_CHARS);
    const bigIntMsg = stringToBigInt(chunk);
    const encrypted = encryptValue(bigIntMsg, publicKey);
    chunks.push(encrypted);
  }

  return JSON.stringify(chunks);
}

/**
 * Decrypt a string encrypted with encryptString
 * @param {string} ciphertext - JSON string of encrypted chunks
 * @param {string} privateKey - Private key hex
 * @returns {string} Decrypted plaintext
 */
function decryptString(ciphertext, privateKey) {
  if (!ciphertext || ciphertext.length === 0) return '';

  try {
    const chunks = JSON.parse(ciphertext);
    let plaintext = '';

    for (const chunk of chunks) {
      const decryptedBigInt = decryptValue(chunk, privateKey);
      plaintext += bigIntToString(decryptedBigInt);
    }

    return plaintext;
  } catch (e) {
    // legacy/plaintext
    // ecc decrypt failed
    return ciphertext;
  }
}

/**
 * Serialize key pair for storage
 */
function serializeKeyPair(keyPair) {
  return JSON.parse(JSON.stringify(keyPair));
}

/**
 * Deserialize key pair from storage
 */
function deserializeKeyPair(data) {
  return data;
}

export {
  generateKeyPair,
  encryptString,
  decryptString,
  encryptValue,
  decryptValue,
  serializeKeyPair,
  deserializeKeyPair,
  pointAdd,
  pointDouble,
  scalarMultiply,
  isOnCurve,
  CURVE
};
