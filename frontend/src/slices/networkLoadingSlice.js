import { createSlice } from '@reduxjs/toolkit';

const initialState = {
  pendingCount: 0,
};

const networkLoadingSlice = createSlice({
  name: 'networkLoading',
  initialState,
  reducers: {
    networkRequestStarted: (state) => {
      state.pendingCount += 1;
    },
    networkRequestFinished: (state) => {
      state.pendingCount = Math.max(0, state.pendingCount - 1);
    },
    resetNetworkLoading: (state) => {
      state.pendingCount = 0;
    },
  },
});

export const {
  networkRequestStarted,
  networkRequestFinished,
  resetNetworkLoading,
} = networkLoadingSlice.actions;

export default networkLoadingSlice.reducer;
