/**
 * Product Controller — Secured with ECC Encryption + HMAC
 *
 * Performance: decrypted products are cached in-memory keyed by
 * `${id}_${updatedAt}` so ECC BigInt ops only run once per product
 * version. Cache is invalidated on update/delete.
 */

import asyncHandler from 'express-async-handler';
import Product from '../models/productModel.js';
import { getActiveKey, getKeyByVersion, getHmacSecret } from '../crypto/keyManager.js';
import * as eccCrypto from '../crypto/ecc.js';
import { hmac, verifyHmac } from '../crypto/hmac.js';
import {
  decryptProductData,
  isLikelyEccCiphertext,
  invalidateCacheById
} from '../utils/productCrypto.js';

// ==================== HELPERS ====================

async function encryptProductData(data) {
  const key = await getActiveKey('ECC', 'PRODUCT_DATA');
  const encrypted = { ...data };

  if (data.name && !isLikelyEccCiphertext(data.name))
    encrypted.name = eccCrypto.encryptString(data.name, key.publicKey);
  if (data.description && !isLikelyEccCiphertext(data.description))
    encrypted.description = eccCrypto.encryptString(data.description, key.publicKey);
  if (data.brand && !isLikelyEccCiphertext(data.brand))
    encrypted.brand = eccCrypto.encryptString(data.brand, key.publicKey);

  encrypted.encryptionKeyVersion = key.version;
  return encrypted;
}

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

function verifyProductIntegrity(product) {
  if (!product.dataHmac) return true;
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

  products.forEach(p => {
    if (!verifyProductIntegrity(p))
      console.warn(`⚠️ HMAC integrity check failed for product ${p._id}`);
  });

  const decryptedProducts = await Promise.all(products.map(decryptProductData));
  res.status(200).json(decryptedProducts);
});

// GET a product by ID (public)
const getProductById = asyncHandler(async (req, res) => {
  const product = await Product.findById(req.params.productId);

  if (product) {
    if (!verifyProductIntegrity(product))
      console.warn(`⚠️ HMAC integrity check failed for product ${product._id}`);
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
  const products = await Product.find({ category: req.params.myCategory });

  if (products.length === 0) {
    res.status(404);
    throw new Error('No products found');
  }

  const decryptedProducts = await Promise.all(products.map(decryptProductData));
  res.status(200).json(decryptedProducts);
});

// POST create product (admin only)
const createProduct = asyncHandler(async (req, res) => {
  const {
    name, brand, description, category: initialCategory, subcategory, sku, upc,
    compatibleVehicles, fitmentNotes, material, color, weightKg, dimensionsCm,
    warrantyMonths, price, countInStock, image, images, tags, isFeatured
  } = req.body;

  const imageName = req.file ? req.file.filename : null;
  const category = initialCategory ? initialCategory.toUpperCase() : undefined;

  const encrypted = await encryptProductData({ name, description, brand });

  const productData = {
    name: encrypted.name,
    brand: encrypted.brand,
    sku, upc,
    description: encrypted.description,
    category, subcategory,
    compatibleVehicles: Array.isArray(compatibleVehicles) ? compatibleVehicles : (compatibleVehicles ? [compatibleVehicles] : []),
    fitmentNotes, material, color, weightKg, dimensionsCm, warrantyMonths,
    price, countInStock,
    image: imageName || image || null,
    images: Array.isArray(images) ? images : [],
    tags: Array.isArray(tags) ? tags : [],
    isFeatured,
    encryptionKeyVersion: encrypted.encryptionKeyVersion
  };

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
  const product = await Product.findById(req.body.productId);

  if (product) {
    const imageName = req.file ? req.file.filename : null;
    const key = await getActiveKey('ECC', 'PRODUCT_DATA');

    if (req.body.name)
      product.name = isLikelyEccCiphertext(req.body.name) ? req.body.name : eccCrypto.encryptString(req.body.name, key.publicKey);
    if (req.body.brand)
      product.brand = isLikelyEccCiphertext(req.body.brand) ? req.body.brand : eccCrypto.encryptString(req.body.brand, key.publicKey);
    if (req.body.description)
      product.description = isLikelyEccCiphertext(req.body.description) ? req.body.description : eccCrypto.encryptString(req.body.description, key.publicKey);

    product.sku             = req.body.sku             || product.sku;
    product.upc             = req.body.upc             || product.upc;
    product.category        = req.body.category        ? req.body.category.toUpperCase() : product.category;
    product.subcategory     = req.body.subcategory     || product.subcategory;
    product.compatibleVehicles = req.body.compatibleVehicles || product.compatibleVehicles;
    product.fitmentNotes    = req.body.fitmentNotes    || product.fitmentNotes;
    product.material        = req.body.material        || product.material;
    product.color           = req.body.color           || product.color;
    product.weightKg        = req.body.weightKg        ?? product.weightKg;
    product.dimensionsCm    = req.body.dimensionsCm    || product.dimensionsCm;
    product.warrantyMonths  = req.body.warrantyMonths  ?? product.warrantyMonths;
    product.price           = req.body.price           ?? product.price;
    product.countInStock    = req.body.countInStock    ?? product.countInStock;
    product.image           = imageName                || product.image;
    product.images          = req.body.images          || product.images;
    product.tags            = req.body.tags            || product.tags;
    product.isFeatured      = req.body.isFeatured      ?? product.isFeatured;
    product.encryptionKeyVersion = key.version;
    product.dataHmac        = computeProductHmac(product);

    // Invalidate cache before save so updatedAt change produces new cache key
    invalidateCacheById(product._id);

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
  invalidateCacheById(productId);
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

  if      (filter === 'pLow')     products = await Product.find({}).sort({ price: 1 });
  else if (filter === 'pHigh')    products = await Product.find({}).sort({ price: -1 });
  else if (filter === 'ratingHigh') products = await Product.find({}).sort({ rating: -1 });
  else if (filter === 'ratingLow')  products = await Product.find({}).sort({ rating: 1 });
  else if (filter === 'stock')    products = await Product.find({ countInStock: { $gt: 0 } }).sort({ countInStock: -1 });
  else if (filter === 'featured') products = await Product.find({ isFeatured: true }).sort({ createdAt: -1 });
  else if (filter === 'alphaA' || filter === 'alphaZ') products = await Product.find({});
  else { res.status(404); throw new Error('Invalid filter'); }

  const decryptedProducts = await Promise.all(products.map(decryptProductData));

  if (filter === 'alphaA')
    decryptedProducts.sort((a, b) => (a.name || '').localeCompare(b.name || ''));
  else if (filter === 'alphaZ')
    decryptedProducts.sort((a, b) => (b.name || '').localeCompare(a.name || ''));

  res.status(200).json(decryptedProducts);
});

// GET products by search (public)
const getProductsBySearch = asyncHandler(async (req, res) => {
  const search = req.params.search.toLowerCase();
  const allProducts = await Product.find({});

  const decrypted = await Promise.all(allProducts.map(decryptProductData));

  const matched = decrypted.filter(p => {
    const fields = [
      p.name, p.brand, p.description, p.sku, p.upc,
      p.category, p.subcategory, ...(p.tags || []), ...(p.compatibleVehicles || [])
    ];
    return fields.some(f => f && String(f).toLowerCase().includes(search));
  });

  if (matched.length === 0) {
    res.status(404);
    throw new Error('No products found');
  }

  res.status(200).json(matched);
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
