import { useEffect, useRef } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { useGetAllProductQuery } from '../slices/productsApiSlice';
import { 
  updateCartItemStock, 
  syncCartWithStock, 
  removeOutOfStockItems 
} from '../slices/cartSlice';
import { showWarning, showError } from '../utils/toast';

export const useStockSync = () => {
  const dispatch = useDispatch();
  const { cartItems } = useSelector((state) => state.cart);
  const { data: products, isLoading, error } = useGetAllProductQuery();
  const lastStockUpdate = useRef({});

  // Sync cart with current product stock
  useEffect(() => {
    if (products && cartItems.length > 0) {
      dispatch(syncCartWithStock({ products }));
    }
  }, [products, dispatch]);

  // watch stock
  useEffect(() => {
    if (!products || cartItems.length === 0) return;

    cartItems.forEach(cartItem => {
      const product = products.find(p => p._id === cartItem._id);
      if (product) {
        const lastStock = lastStockUpdate.current[cartItem._id];
        
        // update cart
        if (lastStock !== undefined && lastStock !== product.countInStock) {
          dispatch(updateCartItemStock({ 
            productId: cartItem._id, 
            newStock: product.countInStock 
          }));

          // warn on drop
          if (lastStock > product.countInStock) {
            const decrease = lastStock - product.countInStock;
            if (decrease > 0) {
              showWarning(`${product.name} stock decreased by ${decrease}. Current stock: ${product.countInStock}`);
            }
          }

          // warn out of stock
          if (product.countInStock === 0 && lastStock > 0) {
            showError(`${product.name} is now out of stock and has been removed from your cart`);
          }
        }

        // remember stock
        lastStockUpdate.current[cartItem._id] = product.countInStock;
      }
    });
  }, [products, cartItems, dispatch]);

  // remove out-of-stock items
  useEffect(() => {
    if (products && cartItems.length > 0) {
      const outOfStockItems = cartItems.filter(item => 
        item.countInStock === 0
      );

      if (outOfStockItems.length > 0) {
        dispatch(removeOutOfStockItems());
        outOfStockItems.forEach(item => {
          showWarning(`${item.name} is out of stock and has been removed from your cart`);
        });
      }
    }
  }, [products, cartItems, dispatch]);

  // get stock
  const getCurrentStock = (productId) => {
    if (!products) return null;
    const product = products.find(p => p._id === productId);
    return product ? product.countInStock : null;
  };

  // check stock
  const isInStock = (productId, quantity = 1) => {
    const stock = getCurrentStock(productId);
    return stock !== null && stock >= quantity;
  };

  // stock status
  const getStockStatus = (productId) => {
    const stock = getCurrentStock(productId);
    if (stock === null) return { status: 'loading', text: 'Checking stock...', color: 'text-gray-500' };
    if (stock === 0) return { status: 'out', text: 'Out of Stock', color: 'text-red-500' };
    if (stock <= 5) return { status: 'low', text: `Only ${stock} left!`, color: 'text-orange-500' };
    return { status: 'in', text: `In Stock (${stock})`, color: 'text-green-500' };
  };

  return {
    isLoading,
    error,
    getCurrentStock,
    isInStock,
    getStockStatus,
    products
  };
};
