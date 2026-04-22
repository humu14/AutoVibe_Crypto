import { configureStore } from '@reduxjs/toolkit';
import authReducer from './slices/authSlice';
import cartSlice from './slices/cartSlice';
import { apiSlice } from './slices/apiSlice';
import otpSliceReducer from './slices/otpSlice';
import networkLoadingReducer from './slices/networkLoadingSlice';

const store = configureStore({
  reducer: {
    [apiSlice.reducerPath]: apiSlice.reducer,
    cart: cartSlice,
    auth: authReducer,
    otpInfo: otpSliceReducer,
    networkLoading: networkLoadingReducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware().concat(apiSlice.middleware),
  devTools: true,
});

export default store;
