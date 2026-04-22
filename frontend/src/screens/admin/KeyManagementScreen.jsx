import { useState, useEffect } from 'react';
import { toast } from 'sonner';

/**
 * Admin Key Management Screen
 * View, rotate, and revoke encryption keys
 */
const KeyManagementScreen = () => {
  const [keys, setKeys] = useState([]);
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(null);

  useEffect(() => {
    fetchKeys();
    fetchStatus();
  }, []);

  const fetchKeys = async () => {
    try {
      const res = await fetch('/api/keys');
      const data = await res.json();
      if (res.ok) setKeys(data);
    } catch (err) {
      toast.error('Failed to load keys');
    } finally {
      setLoading(false);
    }
  };

  const fetchStatus = async () => {
    try {
      const res = await fetch('/api/keys/status');
      const data = await res.json();
      if (res.ok) setStatus(data);
    } catch (err) {
      console.error('Failed to load key status');
    }
  };

  const handleRotate = async (keyId) => {
    if (!confirm(`Are you sure you want to rotate key ${keyId}?`)) return;
    setActionLoading(keyId);
    try {
      const res = await fetch(`/api/keys/rotate/${keyId}`, { method: 'POST' });
      const data = await res.json();
      if (res.ok) {
        toast.success(`Key rotated: ${data.oldKeyId} → ${data.newKeyId}`);
        fetchKeys();
        fetchStatus();
      } else {
        toast.error(data.message || 'Rotation failed');
      }
    } catch (err) {
      toast.error('Rotation failed');
    } finally {
      setActionLoading(null);
    }
  };

  const handleRevoke = async (keyId) => {
    if (!confirm(`WARNING: Revoking key ${keyId} will make data encrypted with it unrecoverable. Continue?`)) return;
    setActionLoading(keyId);
    try {
      const res = await fetch(`/api/keys/revoke/${keyId}`, { method: 'POST' });
      const data = await res.json();
      if (res.ok) {
        toast.success(`Key revoked: ${keyId}`);
        fetchKeys();
        fetchStatus();
      } else {
        toast.error(data.message || 'Revocation failed');
      }
    } catch (err) {
      toast.error('Revocation failed');
    } finally {
      setActionLoading(null);
    }
  };

  const getStatusColor = (s) => {
    if (s === 'ACTIVE') return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30';
    if (s === 'ROTATED') return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
    return 'bg-red-500/20 text-red-400 border-red-500/30';
  };

  const getAlgoColor = (a) => {
    return a === 'RSA' 
      ? 'bg-blue-500/20 text-blue-400 border-blue-500/30'
      : 'bg-purple-500/20 text-purple-400 border-purple-500/30';
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-emerald-500" />
      </div>
    );
  }

  return (
    <div className="container mx-auto px-4 py-8 max-w-7xl">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white flex items-center gap-3">
          <span className="text-3xl">🔐</span>
          Key Management
        </h1>
        <p className="text-gray-400 mt-2">
          Manage encryption keys for RSA and ECC algorithms
        </p>
      </div>

      {/* Status Cards */}
      {status && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-8">
          {[
            { label: 'Total Keys', value: status.total, color: 'from-blue-600 to-blue-800' },
            { label: 'Active', value: status.active, color: 'from-emerald-600 to-emerald-800' },
            { label: 'Rotated', value: status.rotated, color: 'from-yellow-600 to-yellow-800' },
            { label: 'Revoked', value: status.revoked, color: 'from-red-600 to-red-800' },
            { label: 'Expiring Soon', value: status.expiringSoon, color: 'from-orange-600 to-orange-800' },
          ].map((card, i) => (
            <div key={i} className={`rounded-xl bg-gradient-to-br ${card.color} p-4 shadow-lg`}>
              <p className="text-white/70 text-sm">{card.label}</p>
              <p className="text-3xl font-bold text-white mt-1">{card.value}</p>
            </div>
          ))}
        </div>
      )}

      {/* Keys Table */}
      <div className="bg-gray-900/80 backdrop-blur-xl rounded-xl border border-gray-700/50 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-700/50">
                <th className="text-left py-4 px-6 text-gray-400 text-sm font-semibold">Key ID</th>
                <th className="text-left py-4 px-6 text-gray-400 text-sm font-semibold">Algorithm</th>
                <th className="text-left py-4 px-6 text-gray-400 text-sm font-semibold">Purpose</th>
                <th className="text-left py-4 px-6 text-gray-400 text-sm font-semibold">Status</th>
                <th className="text-left py-4 px-6 text-gray-400 text-sm font-semibold">Version</th>
                <th className="text-left py-4 px-6 text-gray-400 text-sm font-semibold">Created</th>
                <th className="text-left py-4 px-6 text-gray-400 text-sm font-semibold">Expires</th>
                <th className="text-left py-4 px-6 text-gray-400 text-sm font-semibold">Actions</th>
              </tr>
            </thead>
            <tbody>
              {keys.map((key) => (
                <tr key={key.keyId} className="border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors">
                  <td className="py-4 px-6">
                    <code className="text-xs text-gray-300 bg-gray-800 px-2 py-1 rounded">
                      {key.keyId}
                    </code>
                  </td>
                  <td className="py-4 px-6">
                    <span className={`px-2 py-1 rounded-full text-xs font-medium border ${getAlgoColor(key.algorithm)}`}>
                      {key.algorithm}
                    </span>
                  </td>
                  <td className="py-4 px-6 text-gray-300 text-sm">{key.purpose}</td>
                  <td className="py-4 px-6">
                    <span className={`px-2 py-1 rounded-full text-xs font-medium border ${getStatusColor(key.status)}`}>
                      {key.status}
                    </span>
                  </td>
                  <td className="py-4 px-6 text-gray-300 text-center">v{key.version}</td>
                  <td className="py-4 px-6 text-gray-400 text-sm">
                    {new Date(key.createdAt).toLocaleDateString()}
                  </td>
                  <td className="py-4 px-6 text-gray-400 text-sm">
                    {key.expiresAt ? new Date(key.expiresAt).toLocaleDateString() : '—'}
                  </td>
                  <td className="py-4 px-6">
                    {key.status === 'ACTIVE' && (
                      <div className="flex gap-2">
                        <button
                          onClick={() => handleRotate(key.keyId)}
                          disabled={actionLoading === key.keyId}
                          className="px-3 py-1.5 text-xs font-medium rounded-lg 
                            bg-yellow-500/10 text-yellow-400 border border-yellow-500/30
                            hover:bg-yellow-500/20 transition-colors disabled:opacity-50"
                          id={`rotate-${key.keyId}`}
                        >
                          {actionLoading === key.keyId ? '...' : 'Rotate'}
                        </button>
                        <button
                          onClick={() => handleRevoke(key.keyId)}
                          disabled={actionLoading === key.keyId}
                          className="px-3 py-1.5 text-xs font-medium rounded-lg 
                            bg-red-500/10 text-red-400 border border-red-500/30
                            hover:bg-red-500/20 transition-colors disabled:opacity-50"
                          id={`revoke-${key.keyId}`}
                        >
                          Revoke
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {keys.length === 0 && (
          <div className="text-center py-12 text-gray-500">
            No encryption keys found. The system will generate keys on server startup.
          </div>
        )}
      </div>

      {/* Info Panel */}
      <div className="mt-8 grid md:grid-cols-2 gap-6">
        <div className="bg-gray-900/60 rounded-xl border border-gray-700/50 p-6">
          <h3 className="text-lg font-semibold text-blue-400 flex items-center gap-2 mb-3">
            <span>🔑</span> RSA Keys
          </h3>
          <p className="text-gray-400 text-sm leading-relaxed">
            RSA (1024-bit) keys are used for encrypting <strong className="text-gray-200">user personal data</strong> (name, email, phone) 
            and <strong className="text-gray-200">order shipping addresses</strong>. RSA provides secure asymmetric encryption 
            based on the mathematical difficulty of factoring large prime numbers.
          </p>
        </div>
        <div className="bg-gray-900/60 rounded-xl border border-gray-700/50 p-6">
          <h3 className="text-lg font-semibold text-purple-400 flex items-center gap-2 mb-3">
            <span>🔐</span> ECC Keys
          </h3>
          <p className="text-gray-400 text-sm leading-relaxed">
            ECC (secp256k1) keys are used for encrypting <strong className="text-gray-200">product data</strong> (name, description, brand) 
            and <strong className="text-gray-200">review comments</strong> using EC-ElGamal encryption. ECC provides equivalent 
            security to RSA with significantly smaller key sizes.
          </p>
        </div>
      </div>
    </div>
  );
};

export default KeyManagementScreen;
