import {
  networkRequestStarted,
  networkRequestFinished,
} from '../slices/networkLoadingSlice';

const TRACKER_FLAG = '__AUTO_VIBE_FETCH_TRACKER_INSTALLED__';

export function installGlobalFetchTracker(store) {
  if (typeof window === 'undefined') return;
  if (window[TRACKER_FLAG]) return;

  const originalFetch = window.fetch.bind(window);

  window.fetch = async (...args) => {
    store.dispatch(networkRequestStarted());
    try {
      return await originalFetch(...args);
    } finally {
      store.dispatch(networkRequestFinished());
    }
  };

  window[TRACKER_FLAG] = true;
}
