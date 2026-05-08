/**
 * Key Management Module
 * Handles key generation, storage, retrieval, rotation, and revocation
 * for both RSA and ECC keys
 */

import Key from '../models/keyModel.js';
import * as rsa from './rsa.js';
import * as ecc from './ecc.js';

// key cache
let keyCache = {};
let keyEncryptionPair = null;
let warnedUnprotectedPrivateKeyStorage = false;

function hasPersistentKeyEncryptionConfig() {
  return Boolean(
    process.env.KEY_ENCRYPTION_PUBLIC_N &&
    process.env.KEY_ENCRYPTION_PUBLIC_E &&
    process.env.KEY_ENCRYPTION_PRIVATE_N &&
    process.env.KEY_ENCRYPTION_PRIVATE_D
  );
}

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
  if (!hasPersistentKeyEncryptionConfig()) {
    if (!warnedUnprotectedPrivateKeyStorage) {
      console.warn('KEY_ENCRYPTION_* environment variables missing. Storing private keys without at-rest encryption.');
      warnedUnprotectedPrivateKeyStorage = true;
    }
    return privateKey;
  }

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
    try {
      return JSON.parse(plaintext);
    } catch (error) {
      throw new Error('Stored private key payload could not be parsed after decryption');
    }
  }

  return privateKeyField;
}

function isPrivateKeyShapeValid(privateKey, algorithm) {
  if (algorithm === 'RSA') {
    return Boolean(privateKey && typeof privateKey === 'object' && privateKey.n && privateKey.d);
  }

  if (algorithm === 'ECC') {
    return typeof privateKey === 'string' && privateKey.length > 0;
  }

  return false;
}

function canRevealStoredPrivateKey(privateKeyField, algorithm) {
  try {
    const privateKey = revealPrivateKeyFromStorage(privateKeyField);
    return isPrivateKeyShapeValid(privateKey, algorithm);
  } catch {
    return false;
  }
}

async function createActiveKey(config, version = 1) {
  const keyPair = config.generator();
  const privateKey = config.algorithm === 'RSA' ? keyPair.privateKey : keyPair.privateKey;

  return Key.create({
    keyId: generateKeyId(config.algorithm, config.purpose),
    algorithm: config.algorithm,
    purpose: config.purpose,
    publicKey: config.algorithm === 'RSA' ? keyPair.publicKey : keyPair.publicKey,
    privateKey: protectPrivateKeyAtRest(privateKey, config.algorithm),
    status: 'ACTIVE',
    version,
    expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000) // 90 days
  });
}

/** key id */
function generateKeyId(algorithm, purpose) {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 8);
  return `${algorithm}-${purpose}-${timestamp}-${random}`.toLowerCase();
}

/** init keys */
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
      const keyDoc = await createActiveKey(config, 1);

      console.log(`  ✅ ${config.algorithm} key created: ${keyDoc.keyId}`);
    } else {
      const canUseExisting = canRevealStoredPrivateKey(existingKey.privateKey, config.algorithm);

      if (canUseExisting) {
        console.log(`  ✅ ${config.algorithm} key for ${config.purpose} already exists: ${existingKey.keyId}`);
        continue;
      }

      if (!hasPersistentKeyEncryptionConfig()) {
        console.warn(
          `  ⚠️ Existing ${config.algorithm} key for ${config.purpose} cannot be decrypted with runtime-only key encryption pair. Regenerating...`
        );

        existingKey.status = 'REVOKED';
        await existingKey.save();

        const regenerated = await createActiveKey(config, existingKey.version + 1);
        console.log(`  ✅ ${config.algorithm} key regenerated: ${regenerated.keyId}`);
        continue;
      }

      throw new Error(
        `Stored ${config.algorithm} private key for ${config.purpose} is not decryptable. Check KEY_ENCRYPTION_* environment variables.`
      );
    }
  }

  // refresh cache
  await refreshKeyCache();
  console.log('🔐 Key Management System initialized.');
}

/** refresh cache */
async function refreshKeyCache() {
  const activeKeys = await Key.find({ status: 'ACTIVE' });
  keyCache = {};
  for (const key of activeKeys) {
    const cacheKey = `${key.algorithm}:${key.purpose}`;
    try {
      const privateKey = revealPrivateKeyFromStorage(key.privateKey);
      keyCache[cacheKey] = {
        keyId: key.keyId,
        algorithm: key.algorithm,
        purpose: key.purpose,
        publicKey: key.publicKey,
        privateKey,
        version: key.version
      };
    } catch {
      console.warn(`Skipping undecryptable key during cache refresh: ${key.keyId}`);
    }
  }
}

/** get active key */
async function getActiveKey(algorithm, purpose) {
  const cacheKey = `${algorithm}:${purpose}`;

  // cache first
  if (keyCache[cacheKey]) {
    return keyCache[cacheKey];
  }

  // db fallback
  const key = await Key.findOne({ algorithm, purpose, status: 'ACTIVE' });
  if (!key) {
    throw new Error(`No active ${algorithm} key found for ${purpose}`);
  }

  // update cache
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

/** get key by version */
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

/** rotate key */
async function rotateKey(keyId) {
  const oldKey = await Key.findOne({ keyId });
  if (!oldKey) throw new Error('Key not found');
  if (oldKey.status !== 'ACTIVE') throw new Error('Can only rotate active keys');

  // new key pair
  let newKeyPair;
  if (oldKey.algorithm === 'RSA') {
    newKeyPair = rsa.generateKeyPair(1024);
  } else {
    newKeyPair = ecc.generateKeyPair();
  }

  // mark rotated
  oldKey.status = 'ROTATED';
  oldKey.rotatedAt = new Date();
  await oldKey.save();

  // create key
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

  // refresh cache
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

/** revoke key */
async function revokeKey(keyId) {
  const key = await Key.findOne({ keyId });
  if (!key) throw new Error('Key not found');

  const wasActive = key.status === 'ACTIVE';

  key.status = 'REVOKED';
  await key.save();

  // replace active key
  if (wasActive) {
    let newKeyPair;
    if (key.algorithm === 'RSA') {
      newKeyPair = rsa.generateKeyPair(1024);
    } else {
      newKeyPair = ecc.generateKeyPair();
    }

    await Key.create({
      keyId: generateKeyId(key.algorithm, key.purpose),
      algorithm: key.algorithm,
      purpose: key.purpose,
      publicKey: key.algorithm === 'RSA' ? newKeyPair.publicKey : newKeyPair.publicKey,
      privateKey: protectPrivateKeyAtRest(
        key.algorithm === 'RSA' ? newKeyPair.privateKey : newKeyPair.privateKey,
        key.algorithm
      ),
      status: 'ACTIVE',
      version: key.version + 1,
      expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000)
    });
    console.log(`🔑 Automatically generated replacement key for ${key.purpose}`);
  }

  // refresh cache
  await refreshKeyCache();

  console.log(`🔑 Key revoked: ${keyId}`);
  return { keyId, status: 'REVOKED' };
}

/** get all keys */
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
    // never expose private keys
    publicKeyPreview: JSON.stringify(k.publicKey).substring(0, 50) + '...'
  }));
}

/** key status */
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

// hmac secret
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
