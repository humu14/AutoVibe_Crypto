/**
 * Product Controller — Secured with ECC Encryption + HMAC
 * 
 * Product data (name, description, brand) encrypted with ECC (ElGamal)
 * HMAC integrity verification on all product records
 */

import asyncHandler from 'express-async-handler';
import Product from '../models/productModel.js';
import Review from '../models/reviewModel.js';
import { getActiveKey, getKeyByVersion, getHmacSecret } from '../crypto/keyManager.js';
import * as eccCrypto from '../crypto/ecc.js';
import { hmac, verifyHmac } from '../crypto/hmac.js';

// ==================== HELPERS ====================

/**
 * Encrypt product sensitive fields with ECC
 */
async function encryptProductData(data) {
  const key = await getActiveKey('ECC', 'PRODUCT_DATA');
  const encrypted = { ...data };

  if (data.name) encrypted.name = eccCrypto.encryptString(data.name, key.publicKey);
  if (data.description) encrypted.description = eccCrypto.encryptString(data.description, key.publicKey);
  if (data.brand) encrypted.brand = eccCrypto.encryptString(data.brand, key.publicKey);

  encrypted.encryptionKeyVersion = key.version;
  return encrypted;
}

/**
 * Decrypt product sensitive fields
 */
async function decryptProductData(product) {
  try {
    let key;
    if (product.encryptionKeyVersion) {
      try {
        key = await getKeyByVersion('ECC', 'PRODUCT_DATA', product.encryptionKeyVersion);
      } catch {
        key = await getActiveKey('ECC', 'PRODUCT_DATA');
      }
    } else {
      key = await getActiveKey('ECC', 'PRODUCT_DATA');
    }
    const obj = product.toObject ? product.toObject() : { ...product };

    if (obj.name) obj.name = eccCrypto.decryptString(obj.name, key.privateKey);
    if (obj.description) obj.description = eccCrypto.decryptString(obj.description, key.privateKey);
    if (obj.brand) obj.brand = eccCrypto.decryptString(obj.brand, key.privateKey);

    return obj;
  } catch (e) {
    console.error('Product decryption error:', e.message);
    return product.toObject ? product.toObject() : product;
  }
}

/**
 * Compute HMAC for product data integrity
 */
function computeProductHmac(product) {
  const secret = getHmacSecret();
  const fields = [
    product.name || '',
    product.description || '',
    product.brand || '',
    String(product.price || 0),
    String(product.countInStock || 0),
    product.category || ''
  ].join('|');
  return hmac(secret, fields);
}

/**
 * Verify product data integrity
 */
function verifyProductIntegrity(product) {
  if (!product.dataHmac) return true; // Legacy data
  const secret = getHmacSecret();
  const fields = [
    product.name || '',
    product.description || '',
    product.brand || '',
    String(product.price || 0),
    String(product.countInStock || 0),
    product.category || ''
  ].join('|');
  return verifyHmac(secret, fields, product.dataHmac);
}

// ==================== ENDPOINTS ====================

// GET all products (public)
const getProduct = asyncHandler(async (req, res) => {
  const products = await Product.find().sort({ createdAt: -1 });
  
  const decryptedProducts = [];
  for (const product of products) {
    if (!verifyProductIntegrity(product)) {
      console.warn(`⚠️ HMAC integrity check failed for product ${product._id}`);
    }
    const decrypted = await decryptProductData(product);
    decryptedProducts.push(decrypted);
  }
  
  res.status(200).json(decryptedProducts);
});

// GET a product by ID (public)
const getProductById = asyncHandler(async (req, res) => {
  const productId = req.params.productId;
  const product = await Product.findById(productId);
  
  if (product) {
    if (!verifyProductIntegrity(product)) {
      console.warn(`⚠️ HMAC integrity check failed for product ${product._id}`);
    }
    const decrypted = await decryptProductData(product);
    res.status(200).json(decrypted);
  } else {
    res.status(404);
    throw new Error('Product not found');
  }
});

// GET unique categories (public)
const getUniqueCategories = asyncHandler(async (req, res) => {
  const categories = await Product.distinct('category');
  res.status(200).json(categories);
});

// GET products by category (public)
const getCategoryProducts = asyncHandler(async (req, res) => {
  const category = req.params.myCategory;
  const products = await Product.find({ category: category });
  
  if (products.length === 0) {
    res.status(404);
    throw new Error('No products found');
  }
  
  const decryptedProducts = [];
  for (const product of products) {
    decryptedProducts.push(await decryptProductData(product));
  }
  
  res.status(200).json(decryptedProducts);
});

// POST create product (admin only)
const createProduct = asyncHandler(async (req, res) => {
  const { name, brand, description, category: initialCategory, subcategory, sku, upc, 
    compatibleVehicles, fitmentNotes, material, color, weightKg, dimensionsCm, 
    warrantyMonths, price, countInStock, image, images, tags, isFeatured } = req.body;
  
  const imageName = (req.file) ? req.file.filename : null;
  const category = initialCategory ? initialCategory.toUpperCase() : undefined;
  const parsedImages = Array.isArray(images) ? images : [];
  const parsedTags = Array.isArray(tags) ? tags : [];
  const parsedCompatible = Array.isArray(compatibleVehicles) ? compatibleVehicles : (compatibleVehicles ? [compatibleVehicles] : []);

  // Encrypt sensitive fields with ECC
  const encrypted = await encryptProductData({ name, description, brand });

  // Create product with encrypted data
  const productData = {
    name: encrypted.name,
    brand: encrypted.brand,
    sku,
    upc,
    description: encrypted.description,
    category,
    subcategory,
    compatibleVehicles: parsedCompatible,
    fitmentNotes,
    material,
    color,
    weightKg,
    dimensionsCm,
    warrantyMonths,
    price,
    countInStock,
    image: imageName,
    images: parsedImages,
    tags: parsedTags,
    isFeatured,
    encryptionKeyVersion: encrypted.encryptionKeyVersion
  };

  // Compute HMAC
  productData.dataHmac = computeProductHmac(productData);

  const newProduct = await Product.create(productData);
  if (newProduct) {
    res.status(201).json({ message: 'Product created successfully', _id: newProduct._id });
  } else {
    res.status(400);
    throw new Error('Invalid product data');
  }
});

// PUT update product (admin only)
const updateProduct = asyncHandler(async (req, res) => {
  const productId = req.body.productId;
  const product = await Product.findById(productId);
  
  if (product) {
    const imageName = (req.file) ? req.file.filename : null;
    const key = await getActiveKey('ECC', 'PRODUCT_DATA');

    // Re-encrypt changed fields
    if (req.body.name) {
      product.name = eccCrypto.encryptString(req.body.name, key.publicKey);
    }
    if (req.body.brand) {
      product.brand = eccCrypto.encryptString(req.body.brand, key.publicKey);
    }
    if (req.body.description) {
      product.description = eccCrypto.encryptString(req.body.description, key.publicKey);
    }

    product.sku = req.body.sku || product.sku;
    product.upc = req.body.upc || product.upc;
    product.category = (req.body.category ? req.body.category.toUpperCase() : product.category);
    product.subcategory = req.body.subcategory || product.subcategory;
    product.compatibleVehicles = req.body.compatibleVehicles || product.compatibleVehicles;
    product.fitmentNotes = req.body.fitmentNotes || product.fitmentNotes;
    product.material = req.body.material || product.material;
    product.color = req.body.color || product.color;
    product.weightKg = req.body.weightKg ?? product.weightKg;
    product.dimensionsCm = req.body.dimensionsCm || product.dimensionsCm;
    product.warrantyMonths = req.body.warrantyMonths ?? product.warrantyMonths;
    product.price = req.body.price ?? product.price;
    product.countInStock = req.body.countInStock ?? product.countInStock;
    product.image = imageName || product.image;
    product.images = req.body.images || product.images;
    product.tags = req.body.tags || product.tags;
    product.isFeatured = req.body.isFeatured ?? product.isFeatured;
    product.encryptionKeyVersion = key.version;

    // Recompute HMAC
    product.dataHmac = computeProductHmac(product);

    const updatedProduct = await product.save();
    const decrypted = await decryptProductData(updatedProduct);
    
    res.status(200).json(decrypted);
  } else {
    res.status(404);
    throw new Error('Product not found');
  }
});

// DELETE product (admin only)
const deleteProduct = asyncHandler(async (req, res) => {
  const productId = req.body.productId;
  const deletedProduct = await Product.deleteOne({ _id: productId });
  if (deletedProduct) {
    res.status(200).json({ message: 'Product removed' });
  } else {
    res.status(404);
    throw new Error('Product not found');
  }
});

// GET products by filter (public)
const getProductsByFilter = asyncHandler(async (req, res) => {
  const filter = req.params.filter;
  let products;

  if (filter === 'pLow') {
    products = await Product.find({}).sort({ price: 1 });
  } else if (filter === 'pHigh') {
    products = await Product.find({}).sort({ price: -1 });
  } else if (filter === 'ratingHigh') {
    products = await Product.find({}).sort({ rating: -1 });
  } else if (filter === 'ratingLow') {
    products = await Product.find({}).sort({ rating: 1 });
  } else if (filter === 'stock') {
    products = await Product.find({ countInStock: { $gt: 0 } }).sort({ countInStock: -1 });
  } else if (filter === 'featured') {
    products = await Product.find({ isFeatured: true }).sort({ createdAt: -1 });
  } else if (filter === 'alphaA' || filter === 'alphaZ') {
    // For alpha sort, we need to decrypt and sort in-memory
    products = await Product.find({});
  } else {
    res.status(404);
    throw new Error('Invalid filter');
  }

  // Decrypt all products
  const decryptedProducts = [];
  for (const product of products) {
    decryptedProducts.push(await decryptProductData(product));
  }

  // In-memory sort for name-based filters (since names are encrypted)
  if (filter === 'alphaA') {
    decryptedProducts.sort((a, b) => (a.name || '').localeCompare(b.name || ''));
  } else if (filter === 'alphaZ') {
    decryptedProducts.sort((a, b) => (b.name || '').localeCompare(a.name || ''));
  }

  res.status(200).json(decryptedProducts);
});

// GET products by search (public) — searches decrypted data in-memory
const getProductsBySearch = asyncHandler(async (req, res) => {
  const search = req.params.search.toLowerCase();
  const allProducts = await Product.find({});
  
  const matchedProducts = [];
  for (const product of allProducts) {
    const decrypted = await decryptProductData(product);
    
    // Search across decrypted fields
    const searchFields = [
      decrypted.name, decrypted.brand, decrypted.description,
      decrypted.sku, decrypted.upc, decrypted.category,
      decrypted.subcategory, ...(decrypted.tags || []),
      ...(decrypted.compatibleVehicles || [])
    ];

    const matches = searchFields.some(field => 
      field && String(field).toLowerCase().includes(search)
    );

    if (matches) {
      matchedProducts.push(decrypted);
    }
  }

  if (matchedProducts.length === 0) {
    res.status(404);
    throw new Error('No products found');
  }

  res.status(200).json(matchedProducts);
});

export {
  getProduct,
  getProductById,
  createProduct,
  updateProduct,
  deleteProduct,
  getUniqueCategories,
  getCategoryProducts,
  getProductsByFilter,
  getProductsBySearch
};