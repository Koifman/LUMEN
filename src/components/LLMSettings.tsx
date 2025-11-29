import { useState, useEffect } from 'react';
import { LLMProvider } from '../types';
import { storeAPIKey, getAPIKey, removeAPIKey, hasAPIKey } from '../lib/llm';
import { validateAPIKey, getAllProviderMetadata, getProviderMetadata } from '../lib/llm';
import './LLMSettings.css';

// Helper to format validation messages with line breaks
const formatMessage = (message: string) => {
  return message.split('\n').map((line, idx) => (
    <span key={idx}>
      {line}
      {idx < message.split('\n').length - 1 && <br />}
    </span>
  ));
};

interface LLMSettingsProps {
  onClose: () => void;
  onConfigChange?: () => void;
}

export default function LLMSettings({ onClose, onConfigChange }: LLMSettingsProps) {
  const [selectedProvider, setSelectedProvider] = useState<LLMProvider>('openai');
  const [apiKey, setApiKey] = useState('');
  const [isValidating, setIsValidating] = useState(false);
  const [validationStatus, setValidationStatus] = useState<'idle' | 'valid' | 'invalid' | 'error'>('idle');
  const [validationMessage, setValidationMessage] = useState('');

  useEffect(() => {
    // Load saved API key and model for selected provider
    const savedKey = getAPIKey(selectedProvider);
    if (savedKey) {
      setApiKey(savedKey);
    } else {
      setApiKey('');
    }

    // Reset validation
    setValidationStatus('idle');
    setValidationMessage('');
  }, [selectedProvider]);

  const handleSave = () => {
    if (!apiKey.trim()) {
      setValidationMessage('API key cannot be empty');
      setValidationStatus('error');
      return;
    }

    storeAPIKey(selectedProvider, apiKey);
    if (onConfigChange) {
      onConfigChange();
    }
    setValidationMessage('API key saved successfully');
    setValidationStatus('valid');
  };

  const handleValidate = async () => {
    const meta = getProviderMetadata(selectedProvider);

    // For providers that don't require API keys (like Ollama), just check service availability
    if (meta && !meta.requiresApiKey) {
      setIsValidating(true);
      setValidationStatus('idle');
      setValidationMessage('Checking service availability...');

      try {
        // Pass the endpoint URL as the apiKey parameter for validation
        const isValid = await validateAPIKey(selectedProvider, apiKey || '');
        if (isValid) {
          // Save the endpoint URL
          storeAPIKey(selectedProvider, apiKey || 'http://localhost:11434');
          setValidationStatus('valid');
          setValidationMessage('Service is available');
          if (onConfigChange) {
            onConfigChange();
          }
          // Close the settings window after successful validation
          setTimeout(() => {
            onClose();
          }, 500); // Short delay to show success message
        } else {
          setValidationStatus('invalid');
          setValidationMessage('Service is not available. Please ensure the service is running.');
        }
      } catch (error) {
        setValidationStatus('error');
        setValidationMessage(error instanceof Error ? error.message : 'Validation failed');
      } finally {
        setIsValidating(false);
      }
      return;
    }

    // For providers that require API keys
    const trimmedKey = apiKey.trim();
    if (!trimmedKey) {
      setValidationMessage('Please enter an API key first');
      setValidationStatus('error');
      return;
    }

    // Basic format validation for Anthropic
    if (selectedProvider === 'anthropic' && !trimmedKey.startsWith('sk-ant-')) {
      setValidationStatus('invalid');
      setValidationMessage('Invalid API key format. Anthropic keys must start with "sk-ant-"');
      return;
    }

    setIsValidating(true);
    setValidationStatus('idle');
    setValidationMessage('Validating API key...');

    try {
      const isValid = await validateAPIKey(selectedProvider, trimmedKey);
      
      if (isValid) {
        setValidationStatus('valid');
        setValidationMessage('API key is valid ✓\n\nKey has been saved successfully.');
        // Auto-save on successful validation
        storeAPIKey(selectedProvider, trimmedKey);
        setApiKey(trimmedKey); // Update displayed key
        if (onConfigChange) {
          onConfigChange();
        }
        // Close the settings window after successful validation
        setTimeout(() => {
          onClose();
        }, 500); // Short delay to show success message
      } else {
        setValidationStatus('invalid');
        // Provide more specific error message
        if (selectedProvider === 'anthropic') {
          setValidationMessage(
            'API key validation failed.\n\n' +
            '📋 VERIFICATION CHECKLIST:\n' +
            '• Key format: Must start with "sk-ant-"\n' +
            '• Key completeness: Ensure entire key is copied (no missing characters)\n' +
            '• Key status: Verify key is active in Anthropic Console\n' +
            '• No spaces: Remove any leading/trailing spaces\n' +
            '• Credits: You mentioned having 5 credits - verify in Anthropic Console\n\n' +
            '🔍 DEBUGGING STEPS:\n' +
            '1. Press F12 to open browser DevTools\n' +
            '2. Go to Console tab - look for [Anthropic] messages\n' +
            '3. Go to Network tab - filter by "messages" or "anthropic"\n' +
            '4. Try validation again and check:\n' +
            '   - HTTP status code (should see 200, 401, 403, or 400)\n' +
            '   - Response body (click on the request to see details)\n' +
            '   - Any CORS errors (red text in console)\n\n' +
            '💡 COMMON ISSUES:\n' +
            '• Account restrictions: New accounts with few credits may have limits\n' +
            '• Rate limiting: Wait 1 minute and try again\n' +
            '• CORS errors: Check browser console for CORS messages\n' +
            '• Network issues: Check your internet connection\n' +
            '• Browser compatibility: Try a different browser\n\n' +
            '📝 If you see a 400 error but NOT an authentication error, your key might actually be valid!'
          );
        } else {
          setValidationMessage('Invalid API key. Please check and try again.\n\nOpen browser console (F12) for details.');
        }
      }
    } catch (error) {
      setValidationStatus('error');
      const errorMsg = error instanceof Error ? error.message : 'Validation failed';

      setValidationMessage(
        `Validation error occurred:\n\n${errorMsg}\n\n` +
        `Please check:\n` +
        `• Your internet connection\n` +
        `• Browser console (F12) for detailed error logs\n` +
        `• API key format is correct\n` +
        `• No browser extensions blocking requests`
      );
    } finally {
      setIsValidating(false);
    }
  };

  const handleRemove = () => {
    if (confirm('Are you sure you want to remove the API key for this provider?')) {
      removeAPIKey(selectedProvider);
      setApiKey('');
      setValidationStatus('idle');
      setValidationMessage('');
      if (onConfigChange) {
        onConfigChange();
      }
    }
  };

  const hasStoredKey = hasAPIKey(selectedProvider);

  return (
    <div className="llm-settings-overlay" onClick={onClose}>
      <div className="llm-settings-modal" onClick={(e) => e.stopPropagation()}>
        <div className="llm-settings-header">
          <h2>LLM API Configuration</h2>
          <button className="close-button" onClick={onClose}>×</button>
        </div>

        <div className="llm-settings-content">
          <div className="settings-section">
            <label>Provider</label>
            <select
              value={selectedProvider}
              onChange={(e) => setSelectedProvider(e.target.value as LLMProvider)}
              className="provider-select"
            >
              {getAllProviderMetadata().map(meta => (
                <option key={meta.id} value={meta.id}>
                  {meta.name}
                </option>
              ))}
            </select>
            {(() => {
              const meta = getProviderMetadata(selectedProvider);
              return meta?.docsUrl && (
                <p className="help-text">
                  <a href={meta.docsUrl} target="_blank" rel="noopener noreferrer">
                    View {meta.name} Documentation →
                  </a>
                </p>
              );
            })()}
          </div>

          {(() => {
            const meta = getProviderMetadata(selectedProvider);
            if (!meta || !meta.requiresApiKey) {
              return (
                <div className="settings-section">
                  <label>Configuration</label>
                  <p className="help-text">
                    This provider does not require an API key.
                  </p>
                  {meta?.requiresEndpoint && (
                    <div style={{ marginTop: '1rem' }}>
                      <label>Endpoint URL</label>
                      <input
                        type="text"
                        value={apiKey}
                        onChange={(e) => {
                          setApiKey(e.target.value);
                          setValidationStatus('idle');
                          setValidationMessage('');
                        }}
                        placeholder="http://localhost:11434"
                        className="api-key-input"
                      />
                      <p className="help-text">
                        Your local Ollama server endpoint (default: http://localhost:11434)
                      </p>
                    </div>
                  )}
                </div>
              );
            }
            return (
              <div className="settings-section">
                <label>
                  API Key
                  {hasStoredKey && <span className="saved-indicator"> (Saved)</span>}
                </label>
                <input
                  type="password"
                  value={apiKey}
                  onChange={(e) => {
                    setApiKey(e.target.value);
                    setValidationStatus('idle');
                    setValidationMessage('');
                  }}
                  placeholder={`Enter ${meta.name} API key`}
                  className="api-key-input"
                />
                <p className="help-text">
                  Your API key is stored locally in your browser. It never leaves your computer.
                </p>
                {meta.apiKeyUrl && (
                  <p className="help-text">
                    <a href={meta.apiKeyUrl} target="_blank" rel="noopener noreferrer">
                      Get API key from {meta.name} →
                    </a>
                  </p>
                )}
                {meta.requiresEndpoint && (
                  <div className="settings-section" style={{ marginTop: '1rem' }}>
                    <label>Endpoint URL</label>
                    <input
                      type="text"
                      placeholder="https://your-resource.openai.azure.com"
                      className="api-key-input"
                    />
                    <p className="help-text">
                      Your Azure OpenAI endpoint URL
                    </p>
                  </div>
                )}
              </div>
            );
          })()}

          {validationMessage && (
            <div className={`validation-message ${validationStatus}`}>
              {formatMessage(validationMessage)}
            </div>
          )}

          <div className="settings-actions">
            <button
              onClick={handleValidate}
              disabled={isValidating || (getProviderMetadata(selectedProvider)?.requiresApiKey && !apiKey.trim())}
              className="validate-button"
            >
              {isValidating ? 'Validating...' : (getProviderMetadata(selectedProvider)?.requiresApiKey ? 'Validate & Save' : 'Check Service')}
            </button>
            {getProviderMetadata(selectedProvider)?.requiresApiKey && (
              <button
                onClick={handleSave}
                disabled={!apiKey.trim()}
                className="save-button"
              >
                Save
              </button>
            )}
            {hasStoredKey && (
              <button
                onClick={handleRemove}
                className="remove-button"
              >
                Remove
              </button>
            )}
          </div>

          <div className="settings-info">
            <h3>Provider Information</h3>
            {(() => {
              const meta = getProviderMetadata(selectedProvider);
              if (!meta) return null;
              
              return (
                <div>
                  <p><strong>{meta.name}</strong></p>
                  <p className="help-text">{meta.description}</p>
                  {meta.docsUrl && (
                    <p className="help-text">
                      <a href={meta.docsUrl} target="_blank" rel="noopener noreferrer">
                        Documentation →
                      </a>
                    </p>
                  )}
                </div>
              );
            })()}
            <p className="warning-text">
              ⚠️ API usage may incur costs. Check your provider's pricing before use.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

