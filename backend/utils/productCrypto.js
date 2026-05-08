import { getActiveKey, getKeyByVersion } from '../crypto/keyManager.js';
import * as eccCrypto from '../crypto/ecc.js';

// cache map
const decryptCache = new Map();

export function isLikelyEccCiphertext(value) {
  if (typeof value !== 'string' || value.length === 0) return false;
  try {
    const parsed = JSON.parse(value);
    if (!Array.isArray(parsed) || parsed.length === 0) return false;
    return parsed.every(c =>
      c && c.C1 && c.C2 &&
      typeof c.C1.x === 'string' && typeof c.C2.x === 'string'
    );
  } catch {
    return false;
  }
}

function cacheKey(product) {
  const id = product._id ? product._id.toString() : String(product._id);
  const ts = product.updatedAt ? new Date(product.updatedAt).getTime() : 0;
  return `${id}_${ts}`;
}

export function invalidateCacheById(id) {
  const prefix = id.toString() + '_';
  for (const k of decryptCache.keys()) {
    if (k.startsWith(prefix)) decryptCache.delete(k);
  }
}

export async function decryptProductData(product) {
  const key = cacheKey(product);
  if (decryptCache.has(key)) return decryptCache.get(key);

  try {
    let eccKey;
    if (product.encryptionKeyVersion) {
      try {
        eccKey = await getKeyByVersion('ECC', 'PRODUCT_DATA', product.encryptionKeyVersion);
      } catch {
        eccKey = await getActiveKey('ECC', 'PRODUCT_DATA');
      }
    } else {
      eccKey = await getActiveKey('ECC', 'PRODUCT_DATA');
    }

    const obj = product.toObject ? product.toObject() : { ...product };

    if (obj.name && isLikelyEccCiphertext(obj.name))
      obj.name = eccCrypto.decryptString(obj.name, eccKey.privateKey);
    if (obj.description && isLikelyEccCiphertext(obj.description))
      obj.description = eccCrypto.decryptString(obj.description, eccKey.privateKey);
    if (obj.brand && isLikelyEccCiphertext(obj.brand))
      obj.brand = eccCrypto.decryptString(obj.brand, eccKey.privateKey);

    decryptCache.set(key, obj);
    return obj;
  } catch (e) {
    console.error('productCrypto decryptProductData error:', e.message);
    return product.toObject ? product.toObject() : product;
  }
}

/** decrypt only product name */
export async function decryptProductName(product) {
  if (!product) return product;
  const name = product.name;
  if (!isLikelyEccCiphertext(name)) return product;

  try {
    let eccKey;
    if (product.encryptionKeyVersion) {
      try {
        eccKey = await getKeyByVersion('ECC', 'PRODUCT_DATA', product.encryptionKeyVersion);
      } catch {
        eccKey = await getActiveKey('ECC', 'PRODUCT_DATA');
      }
    } else {
      eccKey = await getActiveKey('ECC', 'PRODUCT_DATA');
    }
    return { ...product, name: eccCrypto.decryptString(name, eccKey.privateKey) };
  } catch (e) {
    console.error('productCrypto decryptProductName error:', e.message);
    return product;
  }
}
