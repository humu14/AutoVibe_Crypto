/**
 * Order Controller — Secured with RSA Encryption + HMAC
 * Shipping address and payment email encrypted with RSA
 */

import asyncHandler from 'express-async-handler';
import Order from '../models/orderModel.js';
import Product from '../models/productModel.js';
import User from '../models/userModel.js';
import { getActiveKey, getKeyByVersion, getHmacSecret } from '../crypto/keyManager.js';
import * as rsaCrypto from '../crypto/rsa.js';
import { hmac, verifyHmac } from '../crypto/hmac.js';
import { decryptProductData, decryptProductName } from '../utils/productCrypto.js';


async function encryptOrderData(orderData) {
  const key = await getActiveKey('RSA', 'ORDER_DATA');
  
  if (orderData.shippingAddress) {
    orderData.shippingAddress = {
      address: rsaCrypto.encryptString(orderData.shippingAddress.address, key.publicKey),
      city: rsaCrypto.encryptString(orderData.shippingAddress.city, key.publicKey),
      postalCode: rsaCrypto.encryptString(orderData.shippingAddress.postalCode, key.publicKey),
      country: rsaCrypto.encryptString(orderData.shippingAddress.country, key.publicKey),
    };
  }
  
  orderData.encryptionKeyVersion = key.version;
  return orderData;
}

async function decryptOrderData(order) {
  try {
    let key;
    if (order.encryptionKeyVersion) {
      try {
        key = await getKeyByVersion('RSA', 'ORDER_DATA', order.encryptionKeyVersion);
      } catch {
        key = await getActiveKey('RSA', 'ORDER_DATA');
      }
    } else {
      key = await getActiveKey('RSA', 'ORDER_DATA');
    }
    const obj = order.toObject ? order.toObject() : { ...order };

    const looksEncrypted = (value) => {
      if (typeof value !== 'string') return false;
      return /^\s*\[\s*"[0-9A-Fa-f]+"(?:\s*,\s*"[0-9A-Fa-f]+")*\s*\]\s*$/.test(value);
    };

    const decryptUserField = async (user) => {
      if (!user || typeof user !== 'object') return user;

      const encryptedName = user.name;
      if (!encryptedName || !looksEncrypted(encryptedName)) return user;

      const tryDecrypt = (privateKey) => {
        try {
          return rsaCrypto.decryptString(encryptedName, privateKey);
        } catch {
          return null;
        }
      };

      if (user.encryptionKeyVersion) {
        try {
          const versionedKey = await getKeyByVersion('RSA', 'USER_DATA', user.encryptionKeyVersion);
          const versionedName = tryDecrypt(versionedKey.privateKey);
          if (versionedName && !looksEncrypted(versionedName)) {
            user.name = versionedName;
            return user;
          }
        } catch {
          // fallback to active key
        }
      }

      try {
        const activeUserKey = await getActiveKey('RSA', 'USER_DATA');
        const activeName = tryDecrypt(activeUserKey.privateKey);
        if (activeName && !looksEncrypted(activeName)) {
          user.name = activeName;
        }
      } catch {
        // keep original value
      }

      return user;
    };

    if (obj.shippingAddress) {
      obj.shippingAddress = {
        address: rsaCrypto.decryptString(obj.shippingAddress.address, key.privateKey),
        city: rsaCrypto.decryptString(obj.shippingAddress.city, key.privateKey),
        postalCode: rsaCrypto.decryptString(obj.shippingAddress.postalCode, key.privateKey),
        country: rsaCrypto.decryptString(obj.shippingAddress.country, key.privateKey),
      };
    }

    if (obj.paymentResult && obj.paymentResult.email_address) {
      obj.paymentResult.email_address = rsaCrypto.decryptString(obj.paymentResult.email_address, key.privateKey);
    }

    if (obj.user && typeof obj.user === 'object') {
      obj.user = await decryptUserField(obj.user);
    }

    return obj;
  } catch (e) {
    console.error('Order decryption error:', e.message);
    return order.toObject ? order.toObject() : order;
  }
}

function computeOrderHmac(order) {
  const secret = getHmacSecret();
  const fields = [
    String(order.user || ''),
    String(order.totalPrice || 0),
    order.paymentMethod || '',
    JSON.stringify(order.shippingAddress || {}),
  ].join('|');
  return hmac(secret, fields);
}

function isOrderOwnerOrAdmin(req, orderUserId) {
  if (!req.user) return false;
  if (req.user.role === 'admin' || req.user.isAdmin) return true;
  return String(req.user._id) === String(orderUserId);
}


const addOrderItems = asyncHandler(async (req, res) => {
  const {
    orderItems, shippingAddress, paymentMethod,
    itemsPrice, taxPrice, shippingPrice, totalPrice,
  } = req.body;

  if (orderItems && orderItems.length === 0) {
    res.status(400);
    throw new Error('No order items');
  }

  // check stock
  for (const item of orderItems) {
    const product = await Product.findById(item._id);
    if (!product) {
      res.status(400);
      throw new Error(`Product ${item.name || item._id} not found`);
    }
    if (product.countInStock < item.qty) {
      res.status(400);
      throw new Error(`Insufficient stock for ${item.name || item._id}. Available: ${product.countInStock}`);
    }
  }

  try {
    // update stock
    for (const item of orderItems) {
      const product = await Product.findById(item._id);
      if (product) {
        product.countInStock -= item.qty;
        await product.save();
      }
    }

    // encrypt shipping
    const encryptedData = await encryptOrderData({ shippingAddress });

    const order = new Order({
      orderItems: orderItems.map((x) => ({
        ...x,
        product: x._id,
        _id: undefined,
      })),
      user: req.user._id,
      shippingAddress: encryptedData.shippingAddress,
      paymentMethod,
      itemsPrice,
      taxPrice,
      shippingPrice,
      totalPrice,
      encryptionKeyVersion: encryptedData.encryptionKeyVersion
    });

    // compute hmac
    order.dataHmac = computeOrderHmac(order);

    const createdOrder = await order.save();
    res.status(201).json(createdOrder);
  } catch (error) {
    console.error('Error creating order:', error);
    res.status(500);
    throw new Error('Failed to create order. Please try again.');
  }
});

const getAllOrders = asyncHandler(async (req, res) => {
  try {
    const orders = await Order.find({})
      .sort({ createdAt: -1 })
      .populate('user', 'name email encryptionKeyVersion');
    if (orders) {
      const decryptedOrders = [];
      for (const order of orders) {
        decryptedOrders.push(await decryptOrderData(order));
      }
      res.json(decryptedOrders);
    } else {
      res.status(404);
      throw new Error('Orders not found');
    }
  } catch (error) {
    console.error('Error in getAllOrders:', error);
    res.status(500).json({ message: 'Internal server error', error: error.message });
  }
});

const getOrderById = asyncHandler(async (req, res) => {
  try {
    const order = await Order.findById(req.params.orderId).populate('user', 'name email encryptionKeyVersion');
    if (order) {
      if (!isOrderOwnerOrAdmin(req, order.user?._id || order.user)) {
        res.status(403);
        throw new Error('Not authorized to view this order');
      }
      const decrypted = await decryptOrderData(order);
      res.json(decrypted);
    } else {
      res.status(404);
      throw new Error('Order not found');
    }
  } catch (error) {
    console.error('Error in getOrderById:', error);
    res.status(500).json({ message: 'Internal server error', error: error.message });
  }
});

const updateOrderToPaid = asyncHandler(async (req, res) => {
  const order = await Order.findById(req.params.orderId);
  if (order) {
    if (!isOrderOwnerOrAdmin(req, order.user)) {
      res.status(403);
      throw new Error('Not authorized to update this order');
    }

    if (order.isCancelled) {
      res.status(400);
      throw new Error('Cancelled orders cannot be marked as paid');
    }

    const hasManualStatus = typeof req.body.isPaid === 'boolean';
    const nextIsPaid = hasManualStatus ? req.body.isPaid : true;

    if (order.isPaid === nextIsPaid) {
      const currentOrder = await Order.findById(req.params.orderId);
      return res.json(currentOrder);
    }

    order.isPaid = nextIsPaid;
    order.paidAt = nextIsPaid ? Date.now() : undefined;

    if (nextIsPaid) {
      const key = await getActiveKey('RSA', 'ORDER_DATA');
      order.paymentResult = req.body.payer
        ? {
            id: req.body.id,
            status: req.body.status,
            update_time: req.body.update_time,
            email_address: rsaCrypto.encryptString(req.body.payer.email_address, key.publicKey),
          }
        : {
            id: req.body.id || `manual-${order._id}`,
            status: req.body.status || 'MANUAL_PAID',
            update_time: req.body.update_time || new Date().toISOString(),
            email_address: req.body.email_address || '',
          };
    } else {
      order.paymentResult = {};
    }

    // recompute hmac
    order.dataHmac = computeOrderHmac(order);
    
    const updateOrder = await order.save();

    const pointsAchieved = order.totalPrice / 100;
    const pointUser = await User.findById(order.user);
    if (pointUser) {
      pointUser.points = nextIsPaid
        ? pointUser.points + pointsAchieved
        : Math.max(0, pointUser.points - pointsAchieved);
      await pointUser.save();
    }

    res.json(updateOrder);
  } else {
    res.status(404);
    throw new Error('Order not found');
  }
});

const updateOrderPaymentStatus = asyncHandler(async (req, res) => {
  const order = await Order.findById(req.params.orderId);
  if (!order) {
    res.status(404);
    throw new Error('Order not found');
  }

  if (order.isCancelled) {
    res.status(400);
    throw new Error('Cancelled orders cannot be marked as paid');
  }

  const { isPaid } = req.body;
  const nextIsPaid = typeof isPaid === 'boolean' ? isPaid : !order.isPaid;

  if (order.isPaid === nextIsPaid) {
    const currentOrder = await Order.findById(req.params.orderId);
    return res.json(currentOrder);
  }

  order.isPaid = nextIsPaid;
  order.paidAt = nextIsPaid ? Date.now() : undefined;
  order.paymentResult = nextIsPaid
    ? {
        id: req.body.id || `manual-${order._id}`,
        status: req.body.status || 'MANUAL_PAID',
        update_time: req.body.update_time || new Date().toISOString(),
        email_address: req.body.email_address || '',
      }
    : {};

  order.dataHmac = computeOrderHmac(order);

  const updatedOrder = await order.save();

  const pointsAchieved = order.totalPrice / 100;
  const pointUser = await User.findById(order.user);
  if (pointUser) {
    pointUser.points = nextIsPaid
      ? pointUser.points + pointsAchieved
      : Math.max(0, pointUser.points - pointsAchieved);
    await pointUser.save();
  }

  res.json(updatedOrder);
});

const checkStockAvailability = asyncHandler(async (req, res) => {
  const { productId, quantity } = req.body;
  if (!productId || !quantity) {
    res.status(400);
    throw new Error('Product ID and quantity are required');
  }
  const product = await Product.findById(productId);
  if (!product) {
    res.status(404);
    throw new Error('Product not found');
  }
  const decrypted = await decryptProductData(product);
  res.json({
    isAvailable: product.countInStock >= quantity,
    availableStock: product.countInStock,
    requestedQuantity: quantity,
    productName: decrypted.name
  });
});

const checkCartStockAvailability = asyncHandler(async (req, res) => {
  const { items } = req.body;
  if (!items || !Array.isArray(items) || items.length === 0) {
    res.status(400);
    throw new Error('Cart items are required');
  }
  const stockCheckResults = [];
  for (const item of items) {
    const product = await Product.findById(item.productId || item._id);
    if (!product) {
      stockCheckResults.push({ productId: item.productId || item._id, isAvailable: false, error: 'Product not found' });
      continue;
    }
    const isAvailable = product.countInStock >= item.qty;
    const decrypted = await decryptProductData(product);
    stockCheckResults.push({
      productId: product._id,
      productName: decrypted.name,
      isAvailable,
      availableStock: product.countInStock,
      requestedQuantity: item.qty,
      error: isAvailable ? null : `Insufficient stock`
    });
  }
  res.json({ allAvailable: stockCheckResults.every(i => i.isAvailable), results: stockCheckResults });
});

const updateOrderToDelivered = asyncHandler(async (req, res) => {
  const order = await Order.findById(req.params.orderId);
  if (order) {
    order.isDelivered = true;
    order.deliveredAt = Date.now();
    const updateOrder = await order.save();
    res.json(updateOrder);
  } else {
    res.status(404);
    throw new Error('Order not found');
  }
});

const myOrders = asyncHandler(async (req, res) => {
  const requesterIsAdmin = req.user && (req.user.role === 'admin' || req.user.isAdmin);
  if (!requesterIsAdmin && String(req.user._id) !== String(req.params.userId)) {
    res.status(403);
    throw new Error('Not authorized to view these orders');
  }

  const orders = await Order.find({ user: req.params.userId }).sort({ createdAt: -1 }).exec();
  if (orders) {
    const decryptedOrders = [];
    for (const order of orders) {
      decryptedOrders.push(await decryptOrderData(order));
    }
    res.json(decryptedOrders);
  } else {
    res.status(404);
    throw new Error('Orders not found');
  }
});

const updateOrderToCancel = asyncHandler(async (req, res) => {
  const order = await Order.findById(req.body.orderId);
  if (order) {
    if (!isOrderOwnerOrAdmin(req, order.user)) {
      res.status(403);
      throw new Error('Not authorized to cancel this order');
    }

    await Promise.all(
      order.orderItems.map(async (item) => {
        const product = await Product.findById(item.product);
        if (product) {
          product.countInStock += item.qty;
          await product.save();
        }
      })
    );
    order.isCancelled = true;
    const updatedOrder = await order.save();
    res.json(updatedOrder);
  } else {
    res.status(404);
    throw new Error('Order not found');
  }
});

const filterOrder = asyncHandler(async (req, res) => {
  const filter = req.params.filter;
  let query = {};
  
  if (filter === 'paid') query = { isPaid: true };
  else if (filter === 'notPaid') query = { isPaid: false };
  else if (filter === 'delivered') query = { isDelivered: true };
  else if (filter === 'notDelivered') query = { isDelivered: false };
  else if (filter === 'cancelled') query = { isCancelled: true };
  else if (filter === 'notCancelled') query = { isCancelled: false };
  else { res.status(404); throw new Error('Invalid filter'); }

  const orders = await Order.find(query).populate('user', 'name email encryptionKeyVersion').sort({ createdAt: -1 }).exec();
  const decryptedOrders = [];
  for (const order of orders) {
    decryptedOrders.push(await decryptOrderData(order));
  }
  res.status(200).json(decryptedOrders);
});

const myFilterOrders = asyncHandler(async (req, res) => {
  const requesterIsAdmin = req.user && (req.user.role === 'admin' || req.user.isAdmin);
  if (!requesterIsAdmin && String(req.user._id) !== String(req.params.userId)) {
    res.status(403);
    throw new Error('Not authorized to view these orders');
  }

  const filter = req.params.filter;
  let query = { user: req.params.userId };

  if (filter === 'paid') query.isPaid = true;
  else if (filter === 'notPaid') query.isPaid = false;
  else if (filter === 'delivered') query.isDelivered = true;
  else if (filter === 'notDelivered') query.isDelivered = false;
  else if (filter === 'cancelled') query.isCancelled = true;
  else if (filter === 'notCancelled') query.isCancelled = false;
  else { res.status(404); throw new Error('Invalid filter'); }

  const orders = await Order.find(query).populate('user', 'name email encryptionKeyVersion').sort({ createdAt: -1 }).exec();
  const decryptedOrders = [];
  for (const order of orders) {
    decryptedOrders.push(await decryptOrderData(order));
  }
  res.status(200).json(decryptedOrders);
});

const getSales = asyncHandler(async (req, res) => {
  const orders = await Order.find({
    createdAt: { $gte: new Date(Date.now() - 6 * 30 * 24 * 60 * 60 * 1000) },
  });
  const monthlySales = {
    January: 0, February: 0, March: 0, April: 0, May: 0, June: 0,
    July: 0, August: 0, September: 0, October: 0, November: 0, December: 0,
  };
  orders.forEach(order => {
    const month = new Date(order.createdAt).toLocaleString('en-US', { month: 'long' });
    monthlySales[month] += order.totalPrice;
  });
  const salesData = Object.keys(monthlySales).map(month => ({
    month, value: parseFloat(monthlySales[month].toFixed(2))
  }));
  res.json(salesData);
});

const getTopProducts = asyncHandler(async (req, res) => {
  const orders = await Order.find({
    createdAt: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) },
  });
  const productQuantities = {};
  orders.forEach(order => {
    order.orderItems.forEach(item => {
      const { product, qty } = item;
      productQuantities[product] = (productQuantities[product] || 0) + qty;
    });
  });
  const top5Products = Object.keys(productQuantities)
    .map(productId => ({ productId, quantitySold: productQuantities[productId] }))
    .sort((a, b) => b.quantitySold - a.quantitySold)
    .slice(0, 5);
  const productIds = top5Products.map(p => p.productId);
  const products = await Product.find({ _id: { $in: productIds } });
  const decryptedProducts = await Promise.all(products.map(decryptProductData));
  const top5ProductsData = top5Products.map(product => {
    const details = decryptedProducts.find(p => p._id.toString() === product.productId);
    return {
      productId: details?._id || product.productId,
      productName: details?.name || 'Product not found',
      quantitySold: product.quantitySold,
    };
  });
  res.json(top5ProductsData);
});

const getProductCategoriesSortedByOrders = asyncHandler(async (req, res) => {
  try {
    const orders = await Order.find({
      createdAt: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) },
    });
    const categoryCounts = {};
    for (const order of orders) {
      for (const item of order.orderItems) {
        const product = await Product.findById(item.product);
        const cat = product?.category || 'Unknown Category';
        categoryCounts[cat] = (categoryCounts[cat] || 0) + item.qty;
      }
    }
    const sortedCategories = Object.keys(categoryCounts)
      .map(category => ({ category, orderCount: categoryCounts[category] }))
      .sort((a, b) => b.orderCount - a.orderCount);
    res.json(sortedCategories);
  } catch (error) {
    res.status(500).json({ message: 'Something went wrong.' });
  }
});

export {
  addOrderItems, getOrderById, updateOrderToPaid, updateOrderToDelivered,
  updateOrderPaymentStatus,
  getAllOrders, myOrders, updateOrderToCancel, filterOrder, myFilterOrders,
  getSales, getTopProducts, getProductCategoriesSortedByOrders,
  checkStockAvailability, checkCartStockAvailability
};