import { useEffect, useState } from 'react';
import { useSelector } from 'react-redux';

const SHOW_DELAY_MS = 180;

const GlobalLoadingOverlay = () => {
  const pendingCount = useSelector((state) => state.networkLoading.pendingCount);
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    let timer;

    if (pendingCount > 0) {
      timer = setTimeout(() => {
        setVisible(true);
      }, SHOW_DELAY_MS);
    } else {
      setVisible(false);
    }

    return () => {
      if (timer) clearTimeout(timer);
    };
  }, [pendingCount]);

  if (!visible) return null;

  return (
    <div className="fixed inset-0 z-[2000] flex items-center justify-center bg-slate-950/40 backdrop-blur-[2px]">
      <div className="flex flex-col items-center gap-3 rounded-xl border border-emerald-500/20 bg-slate-900/90 px-6 py-5 shadow-2xl">
        <div className="h-10 w-10 animate-spin rounded-full border-4 border-emerald-300/30 border-t-emerald-400" />
        <p className="text-sm font-medium tracking-wide text-emerald-100">Loading data...</p>
      </div>
    </div>
  );
};

export default GlobalLoadingOverlay;
