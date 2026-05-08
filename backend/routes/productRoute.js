import express from 'express';
import {getProduct, createProduct, getProductById, 
    updateProduct, deleteProduct, getUniqueCategories, getCategoryProducts, 
    getProductsByFilter, getProductsBySearch} from '../controllers/productController.js';
import {protect} from '../middleware/authMiddleware.js';
import { requireRole } from '../middleware/rbacMiddleware.js';
import multer from 'multer';

const router = express.Router();
const storage = multer.diskStorage(
    {
        destination: function(req, file, cb) {
            cb(null, 'uploads/');
        },
        filename: function(req, file, cb) {
            cb(null, Date.now() + '-' + file.originalname);
        }
    }
)
const upload = multer({storage: storage});

// public
router.get('/category', getUniqueCategories);
router.get('/:productId', getProductById);
router.get('/', getProduct);
router.get('/category/:myCategory', getCategoryProducts);
router.get('/filter/:filter', getProductsByFilter);
router.get('/search/:search', getProductsBySearch);

// admin only
router.put('/', upload.single('image'), protect, requireRole('admin'), updateProduct);
router.post('/', upload.single('image'), protect, requireRole('admin'), createProduct);
router.delete('/', protect, requireRole('admin'), deleteProduct);


export default router;