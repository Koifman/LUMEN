import { useEffect, useRef, useState } from 'react';
import './EventDetailsModal.css';

interface EventDetailsModalProps {
  event: any;
  isOpen: boolean;
  onClose: () => void;
  title?: string;
}

export function EventDetailsModal({ event, isOpen, onClose, title }: EventDetailsModalProps) {
  const modalRef = useRef<HTMLDivElement>(null);
  const [copied, setCopied] = useState(false);

  // Handle ESC key to close modal
  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };

    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, [isOpen, onClose]);

  // Prevent body scroll when modal is open
  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = '';
    }

    return () => {
      document.body.style.overflow = '';
    };
  }, [isOpen]);

  // Handle click outside modal to close
  const handleBackdropClick = (e: React.MouseEvent) => {
    if (e.target === e.currentTarget) {
      onClose();
    }
  };

  // Handle copy to clipboard
  const handleCopy = async () => {
    const formattedEvent = JSON.stringify(event, null, 2);
    try {
      await navigator.clipboard.writeText(formattedEvent);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  // Reset copied state when modal closes
  useEffect(() => {
    if (!isOpen) {
      setCopied(false);
    }
  }, [isOpen]);

  if (!isOpen) return null;

  // Format the event data as JSON
  const formattedEvent = JSON.stringify(event, null, 2);

  // Generate modal title
  const modalTitle = title || `Event Details ${event?.eventId ? `- Event ID: ${event.eventId}` : ''}`;

  // Syntax highlight JSON
  const syntaxHighlight = (json: string) => {
    json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, (match) => {
      let cls = 'json-number';
      if (/^"/.test(match)) {
        if (/:$/.test(match)) {
          cls = 'json-key';
        } else {
          cls = 'json-string';
        }
      } else if (/true|false/.test(match)) {
        cls = 'json-boolean';
      } else if (/null/.test(match)) {
        cls = 'json-null';
      }
      return `<span class="${cls}">${match}</span>`;
    });
  };

  return (
    <div className="event-modal-backdrop" onClick={handleBackdropClick}>
      <div className="event-modal" ref={modalRef}>
        {/* Modal Header */}
        <div className="event-modal-header">
          <div className="event-modal-title-section">
            <h2 className="event-modal-title">{modalTitle}</h2>
            {event?.timestamp && (
              <span className="event-modal-subtitle">
                {new Date(event.timestamp).toLocaleString()}
              </span>
            )}
            {event?.computer && (
              <span className="event-modal-subtitle">
                Computer: {event.computer}
              </span>
            )}
          </div>
          <button
            className="event-modal-close"
            onClick={onClose}
            aria-label="Close modal"
          >
            ✕
          </button>
        </div>

        {/* Modal Content */}
        <div className="event-modal-content">
          <pre className="event-json-display">
            <code dangerouslySetInnerHTML={{ __html: syntaxHighlight(formattedEvent) }} />
          </pre>
        </div>

        {/* Modal Footer */}
        <div className="event-modal-footer">
          <button
            className="event-modal-button primary"
            onClick={handleCopy}
            disabled={copied}
          >
            {copied ? '✓ Copied!' : '📋 Copy to Clipboard'}
          </button>
          <button className="event-modal-button secondary" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
