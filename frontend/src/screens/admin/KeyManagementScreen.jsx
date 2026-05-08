import { useState, useEffect } from 'react';
import { toast } from 'react-toastify';
import AdminPanelScreen from './AdminPanelScreen.jsx';
import { FaKey, FaExclamationTriangle, FaTrash } from 'react-icons/fa';
import { Button, Modal } from 'react-bootstrap';

/**
 * Admin Key Management Screen
 * View, rotate, and revoke encryption keys
 */
const KeyManagementScreen = () => {
  const [keys, setKeys] = useState([]);
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(null);

  // Modal states
  const [showRotateModal, setShowRotateModal] = useState(false);
  const [keyToRotate, setKeyToRotate] = useState(null);
  const [showRevokeModal, setShowRevokeModal] = useState(false);
  const [keyToRevoke, setKeyToRevoke] = useState(null);

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

  const handleRotateClick = (keyId) => {
    setKeyToRotate(keyId);
    setShowRotateModal(true);
  };

  const handleCloseRotateModal = () => {
    setShowRotateModal(false);
    setKeyToRotate(null);
  };

  const confirmRotate = async () => {
    if (!keyToRotate) return;
    setActionLoading(keyToRotate);
    try {
      const res = await fetch(`/api/keys/rotate/${keyToRotate}`, { method: 'POST' });
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
      handleCloseRotateModal();
    }
  };

  const handleRevokeClick = (keyId) => {
    setKeyToRevoke(keyId);
    setShowRevokeModal(true);
  };

  const handleCloseRevokeModal = () => {
    setShowRevokeModal(false);
    setKeyToRevoke(null);
  };

  const confirmRevoke = async () => {
    if (!keyToRevoke) return;
    setActionLoading(keyToRevoke);
    try {
      const res = await fetch(`/api/keys/revoke/${keyToRevoke}`, { method: 'POST' });
      const data = await res.json();
      if (res.ok) {
        toast.success(`Key revoked: ${keyToRevoke}`);
        fetchKeys();
        fetchStatus();
      } else {
        toast.error(data.message || 'Revocation failed');
      }
    } catch (err) {
      toast.error('Revocation failed');
    } finally {
      setActionLoading(null);
      handleCloseRevokeModal();
    }
  };

  const getStatusStyle = (s) => {
    if (s === 'ACTIVE') return 'bg-green-100 text-green-800 border-green-200';
    if (s === 'ROTATED') return 'bg-yellow-100 text-yellow-800 border-yellow-200';
    return 'bg-red-100 text-red-800 border-red-200';
  };

  const getAlgoStyle = (a) => {
    return a === 'RSA' 
      ? 'bg-blue-100 text-blue-800 border-blue-200'
      : 'bg-purple-100 text-purple-800 border-purple-200';
  };

  if (loading) {
    return (
      <>
        <AdminPanelScreen />
        <div className="flex items-center justify-center min-h-[60vh]">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500" />
        </div>
      </>
    );
  }

  return (
    <>
      <AdminPanelScreen />
      <div className="min-h-screen bg-gradient-to-br from-gray-50 to-blue-50 py-8">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          
          {/* Header */}
          <div className="text-center mb-12">
            <h1 className="text-4xl font-bold text-gray-900 mb-4 flex items-center justify-center gap-4">
              <FaKey className="text-blue-600" />
              Manage Cryptographic Keys
            </h1>
            <p className="text-xl text-gray-600">
              View, rotate, and revoke encryption keys for RSA and ECC algorithms
            </p>
            <div className="w-24 h-1 bg-blue-600 mx-auto mt-6 rounded-full"></div>
          </div>

          {/* Status Cards */}
          {status && (
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-8">
              {[
                { label: 'Total Keys', value: status.total, color: 'bg-blue-50 border-blue-100 text-blue-600' },
                { label: 'Active', value: status.active, color: 'bg-green-50 border-green-100 text-green-600' },
                { label: 'Rotated', value: status.rotated, color: 'bg-yellow-50 border-yellow-100 text-yellow-600' },
                { label: 'Revoked', value: status.revoked, color: 'bg-red-50 border-red-100 text-red-600' },
                { label: 'Expiring Soon', value: status.expiringSoon, color: 'bg-orange-50 border-orange-100 text-orange-600' },
              ].map((card, i) => (
                <div key={i} className={`rounded-2xl shadow-sm border ${card.color.split(' ').slice(0,2).join(' ')} p-6 flex flex-col items-center justify-center`}>
                  <p className="text-sm font-medium text-gray-600">{card.label}</p>
                  <p className={`text-3xl font-bold mt-2 ${card.color.split(' ')[2]}`}>{card.value}</p>
                </div>
              ))}
            </div>
          )}

          {/* Keys Table */}
          <div className="bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Key ID</th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Algorithm</th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Purpose</th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Version</th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Created</th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Expires</th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {keys.map((key) => (
                    <tr key={key.keyId} className="hover:bg-gray-50 transition-colors duration-200">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <code className="text-xs text-gray-600 bg-gray-100 px-2 py-1 rounded border border-gray-200">
                          {key.keyId}
                        </code>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${getAlgoStyle(key.algorithm)}`}>
                          {key.algorithm}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{key.purpose}</td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${getStatusStyle(key.status)}`}>
                          {key.status}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 text-center">v{key.version}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {new Date(key.createdAt).toLocaleDateString()}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {key.expiresAt ? new Date(key.expiresAt).toLocaleDateString() : '—'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        {key.status === 'ACTIVE' && (
                          <div className="flex items-center gap-2">
                            <button
                              onClick={() => handleRotateClick(key.keyId)}
                              disabled={actionLoading === key.keyId}
                              className="inline-flex items-center gap-2 px-3 py-1.5 border border-yellow-300 rounded-md shadow-sm text-xs font-medium text-yellow-700 bg-white hover:bg-yellow-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-yellow-500 disabled:opacity-50 transition-colors duration-200"
                              id={`rotate-${key.keyId}`}
                            >
                              {actionLoading === key.keyId ? '...' : 'Rotate'}
                            </button>
                            <button
                              onClick={() => handleRevokeClick(key.keyId)}
                              disabled={actionLoading === key.keyId}
                              className="inline-flex items-center gap-2 px-3 py-1.5 border border-red-300 rounded-md shadow-sm text-xs font-medium text-red-700 bg-white hover:bg-red-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 disabled:opacity-50 transition-colors duration-200"
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
              <div className="text-center py-20 text-gray-500">
                <FaKey className="w-12 h-12 text-gray-300 mx-auto mb-4" />
                <h3 className="text-xl font-medium text-gray-900 mb-2">No encryption keys found</h3>
                <p>The system will generate keys on server startup.</p>
              </div>
            )}
          </div>

          {/* Info Panel */}
          <div className="mt-8 grid md:grid-cols-2 gap-6">
            <div className="bg-white rounded-2xl shadow-sm border border-gray-100 p-6">
              <h3 className="text-lg font-semibold text-blue-600 flex items-center gap-2 mb-3">
                <span>🔑</span> RSA Keys
              </h3>
              <p className="text-gray-600 text-sm leading-relaxed">
                RSA (1024-bit) keys are used for encrypting <strong className="text-gray-900">user personal data</strong> (name, email, phone) 
                and <strong className="text-gray-900">order shipping addresses</strong>. RSA provides secure asymmetric encryption 
                based on the mathematical difficulty of factoring large prime numbers.
              </p>
            </div>
            <div className="bg-white rounded-2xl shadow-sm border border-gray-100 p-6">
              <h3 className="text-lg font-semibold text-purple-600 flex items-center gap-2 mb-3">
                <span>🔐</span> ECC Keys
              </h3>
              <p className="text-gray-600 text-sm leading-relaxed">
                ECC (secp256k1) keys are used for encrypting <strong className="text-gray-900">product data</strong> (name, description, brand) 
                and <strong className="text-gray-900">review comments</strong> using EC-ElGamal encryption. ECC provides equivalent 
                security to RSA with significantly smaller key sizes.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Rotate Key Confirmation Modal */}
      <Modal 
        show={showRotateModal} 
        onHide={handleCloseRotateModal} 
        size="md"
        className="modal-centered"
        backdrop="static"
        keyboard={false}
        centered
      >
        <Modal.Header closeButton className="bg-yellow-50 border-yellow-200">
          <Modal.Title className="flex items-center gap-2 text-yellow-800">
            <FaExclamationTriangle className="text-yellow-600" />
            Rotate Key
          </Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <div className="text-center py-4">
            <div className="w-16 h-16 bg-yellow-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <FaKey className="w-8 h-8 text-yellow-600" />
            </div>
            <h3 className="text-lg font-semibold text-gray-900 mb-2">
              Rotate key {keyToRotate}?
            </h3>
            <p className="text-gray-600">
              This will generate a new active key for this purpose. The current key will be marked as rotated but will still be available for decrypting historical data.
            </p>
          </div>
        </Modal.Body>
        <Modal.Footer className="bg-yellow-50 border-yellow-200">
          <Button variant="secondary" onClick={handleCloseRotateModal}>
            Cancel
          </Button>
          <Button 
            variant="warning" 
            onClick={confirmRotate}
            disabled={actionLoading === keyToRotate}
            className="bg-yellow-500 hover:bg-yellow-600 border-yellow-500 text-white"
          >
            {actionLoading === keyToRotate ? 'Rotating...' : 'Confirm Rotation'}
          </Button>
        </Modal.Footer>
      </Modal>

      {/* Revoke Key Confirmation Modal */}
      <Modal 
        show={showRevokeModal} 
        onHide={handleCloseRevokeModal} 
        size="md"
        className="modal-centered"
        backdrop="static"
        keyboard={false}
        centered
      >
        <Modal.Header closeButton className="bg-red-50 border-red-200">
          <Modal.Title className="flex items-center gap-2 text-red-800">
            <FaTrash className="text-red-600" />
            Revoke Key
          </Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <div className="text-center py-4">
            <div className="w-16 h-16 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <FaExclamationTriangle className="w-8 h-8 text-red-600" />
            </div>
            <h3 className="text-lg font-semibold text-gray-900 mb-2">
              Are you sure you want to revoke {keyToRevoke}?
            </h3>
            <p className="text-gray-600">
              This action cannot be undone. Any data encrypted specifically with this key version will become <strong className="text-red-600">unrecoverable</strong>. Only proceed if this key has been compromised.
            </p>
          </div>
        </Modal.Body>
        <Modal.Footer className="bg-red-50 border-red-200">
          <Button variant="secondary" onClick={handleCloseRevokeModal}>
            Cancel
          </Button>
          <Button 
            variant="danger" 
            onClick={confirmRevoke}
            disabled={actionLoading === keyToRevoke}
            className="bg-red-600 hover:bg-red-700 border-red-600 text-white"
          >
            {actionLoading === keyToRevoke ? 'Revoking...' : 'Revoke Key'}
          </Button>
        </Modal.Footer>
      </Modal>
    </>
  );
};

export default KeyManagementScreen;
