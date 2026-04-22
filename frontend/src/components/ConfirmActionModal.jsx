import { Modal, Button } from 'react-bootstrap';
import { FaTrash } from 'react-icons/fa';

const ConfirmActionModal = ({
  show,
  title = 'Delete Item',
  message,
  confirmLabel = 'Delete',
  cancelLabel = 'Cancel',
  confirmVariant = 'danger',
  onConfirm,
  onClose,
  isLoading = false,
  loadingLabel = 'Deleting...',
}) => {
  return (
    <Modal
      show={show}
      onHide={onClose}
      size="md"
      className="modal-centered"
      backdrop="static"
      keyboard={!isLoading}
      centered
    >
      <Modal.Header closeButton={!isLoading} className="bg-red-50 border-red-200">
        <Modal.Title className="flex items-center gap-2 text-red-800">
          <FaTrash className="text-red-600" />
          {title}
        </Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <div className="text-center py-4">
          <div className="w-16 h-16 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <FaTrash className="w-8 h-8 text-red-600" />
          </div>
          <h3 className="text-lg font-semibold text-gray-900 mb-2">Are you sure?</h3>
          <p className="text-gray-600 mb-0">{message}</p>
        </div>
      </Modal.Body>
      <Modal.Footer className="bg-red-50 border-red-200">
        <Button variant="secondary" onClick={onClose} disabled={isLoading}>
          {cancelLabel}
        </Button>
        <Button
          variant={confirmVariant}
          onClick={onConfirm}
          disabled={isLoading}
          className="bg-red-600 hover:bg-red-700 border-red-600"
        >
          {isLoading ? loadingLabel : confirmLabel}
        </Button>
      </Modal.Footer>
    </Modal>
  );
};

export default ConfirmActionModal;
