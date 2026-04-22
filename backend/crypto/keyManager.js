/**
 * Key Management Module
 * Handles key generation, storage, retrieval, rotation, and revocation
 * for both RSA and ECC keys
 */

import Key from '../models/keyModel.js';
import * as rsa from './rsa.js';
import * as ecc from './ecc.js';
import { sha256 } from './sha256.js';

// In-memory cache for active keys (avoid DB queries on every request)
let keyCache = {};
let keyEncryptionPair = null;

function getKeyEncryptionPair() {
  if (keyEncryptionPair) {
    return keyEncryptionPair;
  }

  const envPublicN = process.env.KEY_ENCRYPTION_PUBLIC_N;
  const envPublicE = process.env.KEY_ENCRYPTION_PUBLIC_E;
  const envPrivateN = process.env.KEY_ENCRYPTION_PRIVATE_N;
  const envPrivateD = process.env.KEY_ENCRYPTION_PRIVATE_D;

  if (envPublicN && envPublicE && envPrivateN && envPrivateD) {
    keyEncryptionPair = {
      publicKey: { n: envPublicN, e: envPublicE },
      privateKey: { n: envPrivateN, d: envPrivateD }
    };
    return keyEncryptionPair;
  }

  keyEncryptionPair = rsa.generateKeyPair(1024);
  console.warn('KEY_ENCRYPTION_* environment variables missing. Using runtime-only key encryption pair.');
  return keyEncryptionPair;
}

function protectPrivateKeyAtRest(privateKey, algorithm) {
  const pair = getKeyEncryptionPair();
  return {
    encrypted: true,
    protectionAlgorithm: 'RSA',
    originalAlgorithm: algorithm,
    ciphertext: rsa.encryptString(JSON.stringify(privateKey), pair.publicKey)
  };
}

function revealPrivateKeyFromStorage(privateKeyField) {
  if (
    privateKeyField &&
    typeof privateKeyField === 'object' &&
    privateKeyField.encrypted === true &&
    privateKeyField.ciphertext
  ) {
    const pair = getKeyEncryptionPair();
    const plaintext = rsa.decryptString(privateKeyField.ciphertext, pair.privateKey);
    return JSON.parse(plaintext);
  }

  return privateKeyField;
}

/**
 * Generate a unique key ID
 */
function generateKeyId(algorithm, purpose) {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 8);
  return `${algorithm}-${purpose}-${timestamp}-${random}`.toLowerCase();
}

/**
 * Initialize encryption keys on server startup
 * Generates RSA and ECC key pairs if none exist
 */
async function initializeKeys() {
  console.log('🔐 Initializing Key Management System...');

  const keyConfigs = [
    { algorithm: 'RSA', purpose: 'USER_DATA', generator: () => rsa.generateKeyPair(1024) },
    { algorithm: 'RSA', purpose: 'ORDER_DATA', generator: () => rsa.generateKeyPair(1024) },
    { algorithm: 'RSA', purpose: 'SESSION_SIGNING', generator: () => rsa.generateKeyPair(1024) },
    { algorithm: 'ECC', purpose: 'PRODUCT_DATA', generator: () => ecc.generateKeyPair() },
    { algorithm: 'ECC', purpose: 'REVIEW_DATA', generator: () => ecc.generateKeyPair() },
    { algorithm: 'ECC', purpose: 'POST_DATA', generator: () => ecc.generateKeyPair() },
  ];

  for (const config of keyConfigs) {
    const existingKey = await Key.findOne({
      algorithm: config.algorithm,
      purpose: config.purpose,
      status: 'ACTIVE'
    });

    if (!existingKey) {
      console.log(`  Generating ${config.algorithm} key for ${config.purpose}...`);
      const keyPair = config.generator();
      
      const keyDoc = await Key.create({
        keyId: generateKeyId(config.algorithm, config.purpose),
        algorithm: config.algorithm,
        purpose: config.purpose,
        publicKey: config.algorithm === 'RSA' ? keyPair.publicKey : keyPair.publicKey,
        privateKey: protectPrivateKeyAtRest(
          config.algorithm === 'RSA' ? keyPair.privateKey : keyPair.privateKey,
          config.algorithm
        ),
        status: 'ACTIVE',
        version: 1,
        expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000) // 90 days
      });

      console.log(`  ✅ ${config.algorithm} key created: ${keyDoc.keyId}`);
    } else {
      console.log(`  ✅ ${config.algorithm} key for ${config.purpose} already exists: ${existingKey.keyId}`);
    }
  }

  // Refresh cache
  await refreshKeyCache();
  console.log('🔐 Key Management System initialized.');
}

/**
 * Refresh the in-memory key cache
 */
async function refreshKeyCache() {
  const activeKeys = await Key.find({ status: 'ACTIVE' });
  keyCache = {};
  for (const key of activeKeys) {
    const cacheKey = `${key.algorithm}:${key.purpose}`;
    keyCache[cacheKey] = {
      keyId: key.keyId,
      algorithm: key.algorithm,
      purpose: key.purpose,
      publicKey: key.publicKey,
      privateKey: revealPrivateKeyFromStorage(key.privateKey),
      version: key.version
    };
  }
}

/**
 * Get the active key for a given algorithm and purpose
 * @param {string} algorithm - 'RSA' or 'ECC'
 * @param {string} purpose - 'USER_DATA', 'PRODUCT_DATA', etc.
 * @returns {Object} Key data {keyId, publicKey, privateKey, version}
 */
async function getActiveKey(algorithm, purpose) {
  const cacheKey = `${algorithm}:${purpose}`;
  
  // Try cache first
  if (keyCache[cacheKey]) {
    return keyCache[cacheKey];
  }

  // Fall back to DB
  const key = await Key.findOne({ algorithm, purpose, status: 'ACTIVE' });
  if (!key) {
    throw new Error(`No active ${algorithm} key found for ${purpose}`);
  }

  // Update cache
  keyCache[cacheKey] = {
    keyId: key.keyId,
    algorithm: key.algorithm,
    purpose: key.purpose,
    publicKey: key.publicKey,
    privateKey: revealPrivateKeyFromStorage(key.privateKey),
    version: key.version
  };

  return keyCache[cacheKey];
}

/**
 * Get a specific key by version (for decrypting old data)
 * @param {string} algorithm
 * @param {string} purpose
 * @param {number} version
 */
async function getKeyByVersion(algorithm, purpose, version) {
  const key = await Key.findOne({ algorithm, purpose, version });
  if (!key) {
    throw new Error(`Key not found: ${algorithm}/${purpose}/v${version}`);
  }
  return {
    keyId: key.keyId,
    publicKey: key.publicKey,
    privateKey: revealPrivateKeyFromStorage(key.privateKey),
    version: key.version
  };
}

/**
 * Rotate a key — generate new key pair, mark old as ROTATED
 * @param {string} keyId - The key to rotate
 * @returns {Object} New key data
 */
async function rotateKey(keyId) {
  const oldKey = await Key.findOne({ keyId });
  if (!oldKey) throw new Error('Key not found');
  if (oldKey.status !== 'ACTIVE') throw new Error('Can only rotate active keys');

  // Generate new key pair
  let newKeyPair;
  if (oldKey.algorithm === 'RSA') {
    newKeyPair = rsa.generateKeyPair(1024);
  } else {
    newKeyPair = ecc.generateKeyPair();
  }

  // Mark old key as rotated
  oldKey.status = 'ROTATED';
  oldKey.rotatedAt = new Date();
  await oldKey.save();

  // Create new key
  const newKey = await Key.create({
    keyId: generateKeyId(oldKey.algorithm, oldKey.purpose),
    algorithm: oldKey.algorithm,
    purpose: oldKey.purpose,
    publicKey: oldKey.algorithm === 'RSA' ? newKeyPair.publicKey : newKeyPair.publicKey,
    privateKey: protectPrivateKeyAtRest(
      oldKey.algorithm === 'RSA' ? newKeyPair.privateKey : newKeyPair.privateKey,
      oldKey.algorithm
    ),
    status: 'ACTIVE',
    version: oldKey.version + 1,
    expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000)
  });

  // Refresh cache
  await refreshKeyCache();

  console.log(`🔑 Key rotated: ${oldKey.keyId} → ${newKey.keyId}`);
  return {
    oldKeyId: oldKey.keyId,
    newKeyId: newKey.keyId,
    algorithm: newKey.algorithm,
    purpose: newKey.purpose,
    version: newKey.version
  };
}

/**
 * Revoke a key
 * @param {string} keyId
 */
async function revokeKey(keyId) {
  const key = await Key.findOne({ keyId });
  if (!key) throw new Error('Key not found');

  key.status = 'REVOKED';
  await key.save();

  // Refresh cache
  await refreshKeyCache();

  console.log(`🔑 Key revoked: ${keyId}`);
  return { keyId, status: 'REVOKED' };
}

/**
 * Get all keys (admin view)
 */
async function getAllKeys() {
  const keys = await Key.find({}).sort({ createdAt: -1 });
  return keys.map(k => ({
    keyId: k.keyId,
    algorithm: k.algorithm,
    purpose: k.purpose,
    status: k.status,
    version: k.version,
    createdAt: k.createdAt,
    rotatedAt: k.rotatedAt,
    expiresAt: k.expiresAt,
    // Never expose private keys
    publicKeyPreview: JSON.stringify(k.publicKey).substring(0, 50) + '...'
  }));
}

/**
 * Get key status summary
 */
async function getKeyStatus() {
  const keys = await Key.find({});
  const active = keys.filter(k => k.status === 'ACTIVE').length;
  const rotated = keys.filter(k => k.status === 'ROTATED').length;
  const revoked = keys.filter(k => k.status === 'REVOKED').length;
  const expiringSoon = keys.filter(k => 
    k.status === 'ACTIVE' && 
    k.expiresAt && 
    k.expiresAt < new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
  ).length;

  return { total: keys.length, active, rotated, revoked, expiringSoon };
}

// HMAC secret key (derived from environment or hardcoded for lab)
function getHmacSecret() {
  return process.env.HMAC_SECRET || 'autovibe-hmac-secret-key-cse447-2024';
}

export {
  initializeKeys,
  getActiveKey,
  getKeyByVersion,
  rotateKey,
  revokeKey,
  getAllKeys,
  getKeyStatus,
  refreshKeyCache,
  getHmacSecret
};
