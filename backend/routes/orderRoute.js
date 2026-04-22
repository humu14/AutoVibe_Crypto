import express from 'express';
import {addOrderItems, getOrderById, updateOrderToPaid, updateOrderToDelivered, 
    getAllOrders, myOrders, updateOrderToCancel,filterOrder,
    myFilterOrders, getSales, getTopProducts, getProductCategoriesSortedByOrders,
    checkStockAvailability, checkCartStockAvailability} from '../controllers/orderController.js';
import { protect } from '../middleware/authMiddleware.js';
import { requireRole } from '../middleware/rbacMiddleware.js';

const router = express.Router();

router.post('/', protect, addOrderItems);
router.post('/check-stock', checkStockAvailability);
router.post('/check-cart-stock', checkCartStockAvailability);
router.get('/admin', protect, requireRole('admin'), getAllOrders);
router.get('/:orderId', protect, getOrderById);
router.put('/:orderId/pay', protect, updateOrderToPaid);
router.put('/:orderId/deliver', protect, requireRole('admin'), updateOrderToDelivered);
router.get('/myorders/:userId',protect, myOrders);
router.get('/myorders/:userId/filter/:filter',protect, myFilterOrders);
router.put('/cancel',protect, updateOrderToCancel);
router.get('/filter/:filter', protect, requireRole('admin'), filterOrder);
router.get('/admin/totalSale', protect, requireRole('admin'), getSales);
router.get('/admin/topProduct', protect, requireRole('admin'), getTopProducts);
router.get('/admin/topCategory', protect, requireRole('admin'), getProductCategoriesSortedByOrders);

export default router;