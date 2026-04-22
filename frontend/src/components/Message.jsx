import { Alert } from 'react-bootstrap';

const Message = ({ variant, children }) => {
  const resolveMessage = (value) => {
    if (value === null || value === undefined) return '';
    if (typeof value === 'string' || typeof value === 'number') return String(value);

    if (typeof value === 'object') {
      if (typeof value.message === 'string') return value.message;
      if (value.data && typeof value.data.message === 'string') return value.data.message;
      if (value.error && typeof value.error === 'string') return value.error;
      if (typeof value.status === 'number') return `Request failed with status ${value.status}`;
      return 'Something went wrong. Please try again.';
    }

    return String(value);
  };

  return <Alert variant={variant}>{resolveMessage(children)}</Alert>;
};

Message.defaultProps = {
  variant: 'info',
};

export default Message;