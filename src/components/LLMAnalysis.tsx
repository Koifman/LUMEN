import { useState, useEffect, useRef } from 'react';
import ReactMarkdown from 'react-markdown';
import { ParsedData } from '../types';
import { SigmaRuleMatch } from '../lib/sigma/types';
import { LLMProvider } from '../types';
import { formatDataForLLM, sendAnalysisRequest, sendAnalysisRequestWithFiles, getAPIKey, getAvailableModels, getAllProviderMetadata, getProviderMetadata, fetchAvailableModels } from '../lib/llm';
import { saveConversation, loadConversation, clearConversation } from '../lib/llm/storage/conversations';
import LLMSettings from './LLMSettings';
import './LLMAnalysis.css';

interface LLMAnalysisProps {
  data: ParsedData;
  sigmaMatches: Map<string, SigmaRuleMatch[]>;
  onBack: () => void;
}

export default function LLMAnalysis({ data, sigmaMatches, onBack }: LLMAnalysisProps) {
  // Initialize provider to one with API key configured, or default to 'openai'
  const getInitialProvider = (): LLMProvider => {
    const savedConversation = loadConversation();
    if (savedConversation) {
      return savedConversation.provider as LLMProvider;
    }

    // Check for providers with API keys
    const providers: LLMProvider[] = ['openai', 'anthropic', 'google'];
    for (const p of providers) {
      if (getAPIKey(p)) {
        return p;
      }
    }
    return 'openai';
  };

  const [provider, setProvider] = useState<LLMProvider>(getInitialProvider());
  const [model, setModel] = useState<string>('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showSettings, setShowSettings] = useState(false);
  const [viewMode, setViewMode] = useState<'formatted' | 'raw'>('formatted');
  const [maxTokens, setMaxTokens] = useState<number>(4000);
  const [conversationHistory, setConversationHistory] = useState<Array<{ role: 'user' | 'assistant'; content: string }>>([]);
  const [followUpInput, setFollowUpInput] = useState('');
  const [availableModels, setAvailableModels] = useState<string[]>([]);
  const [lastFormattedPrompt, setLastFormattedPrompt] = useState<{ systemPrompt: string; userPrompt: string } | null>(null);
  const [showPromptPreview, setShowPromptPreview] = useState(false);
  const [formattedPrompt, setFormattedPrompt] = useState<any>(null);
  const [configChangeCounter, setConfigChangeCounter] = useState(0);
  const conversationEndRef = useRef<HTMLDivElement>(null);

  // Check if SIGMA analysis has been performed
  const hasSigmaAnalysis = sigmaMatches.size > 0;

  // Load conversation history on mount
  useEffect(() => {
    const savedConversation = loadConversation();
    if (savedConversation) {
      setConversationHistory(savedConversation.messages);
      setProvider(savedConversation.provider as LLMProvider);
      setModel(savedConversation.model);
    }
  }, []); // Only run on mount

  // Auto-scroll to bottom when conversation updates
  useEffect(() => {
    if (conversationEndRef.current) {
      conversationEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [conversationHistory, isAnalyzing]);

  // Save conversation history whenever it changes
  useEffect(() => {
    if (conversationHistory.length > 0) {
      saveConversation({
        provider,
        model,
        messages: conversationHistory,
        lastUpdated: Date.now(),
      });
    }
  }, [conversationHistory, provider, model]);

  useEffect(() => {
    const loadModels = async () => {
      const meta = getProviderMetadata(provider);
      const apiKey = getAPIKey(provider);
      const hasKey = meta?.requiresApiKey ? apiKey !== null : true;

      if (!hasKey && meta?.requiresApiKey) {
        // Check if ANY provider has an API key configured
        const hasAnyApiKey = ['openai', 'anthropic', 'google'].some(p => getAPIKey(p));

        // Only auto-show settings if no provider has an API key
        if (!hasAnyApiKey) {
          setShowSettings(true);
        }

        // Use fallback models when no API key is available
        const fallback = getAvailableModels(provider);
        setAvailableModels(fallback);
        if (fallback.length > 0 && (!model || !fallback.includes(model))) {
          const metaDefault = getProviderMetadata(provider);
          setModel(metaDefault?.defaultModel && fallback.includes(metaDefault.defaultModel) ? metaDefault.defaultModel : fallback[0]);
        }
        return;
      }

      // Only fetch live models if API key is available
      if (hasKey && apiKey) {
        const liveModels = await fetchAvailableModels(provider, { apiKey });
        const fallback = liveModels.length > 0 ? liveModels : getAvailableModels(provider);
        setAvailableModels(fallback);

        if (fallback.length > 0 && (!model || !fallback.includes(model))) {
          const metaDefault = getProviderMetadata(provider);
          setModel(metaDefault?.defaultModel && fallback.includes(metaDefault.defaultModel) ? metaDefault.defaultModel : fallback[0]);
        }
      } else {
        // Use fallback models
        const fallback = getAvailableModels(provider);
        setAvailableModels(fallback);
        if (fallback.length > 0 && (!model || !fallback.includes(model))) {
          const metaDefault = getProviderMetadata(provider);
          setModel(metaDefault?.defaultModel && fallback.includes(metaDefault.defaultModel) ? metaDefault.defaultModel : fallback[0]);
        }
      }
    };

    loadModels();
  }, [provider, configChangeCounter]);

  const handleAnalyze = async () => {
    const meta = getProviderMetadata(provider);
    const apiKey = meta?.requiresApiKey ? getAPIKey(provider) : '';
    const chosenModel = model;

    if (meta?.requiresApiKey && !apiKey) {
      setError('API key not configured. Please configure it in settings.');
      setShowSettings(true);
      return;
    }

    setIsAnalyzing(true);
    setError(null);

    try {
      // Format data for LLM
      const formatted = formatDataForLLM(sigmaMatches, data);
      setLastFormattedPrompt({ systemPrompt: formatted.systemPrompt, userPrompt: formatted.userPrompt });

      // For providers that require endpoint (like Ollama), get it from stored apiKey
      const endpoint = meta?.requiresEndpoint ? getAPIKey(provider) : undefined;

      // Send to LLM
      const response = await sendAnalysisRequest(
        provider,
        {
          apiKey: apiKey || '',
          model: chosenModel || '',
          temperature: 0.7,
          maxTokens: maxTokens || 4000,
          endpoint: endpoint || undefined,
        },
        formatted.systemPrompt,
        formatted.userPrompt
      );

      setAnalysisResult(response.content);
      setConversationHistory([
        { role: 'assistant', content: response.content }
      ]);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to analyze with LLM';
      console.error('LLM Analysis Error:', err);

      // Provide more helpful error messages
      let userFriendlyError = errorMessage;
      if (errorMessage.includes('401') || errorMessage.includes('Invalid API key')) {
        userFriendlyError = 'Invalid API key. Please check your API key in settings and try again.';
      } else if (errorMessage.includes('429') || errorMessage.includes('Rate limit')) {
        userFriendlyError = 'Rate limit exceeded. Please wait a moment and try again, or try a different provider.';
      } else if (errorMessage.includes('400') || errorMessage.includes('Bad request')) {
        userFriendlyError = `Invalid request: ${errorMessage}. Try selecting a different model.`;
      }

      setError(userFriendlyError);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleAnalyzeWithFiles = async () => {
    // Check if provider supports file uploads
    if (provider !== 'openai') {
      setError('File-based analysis is only supported for OpenAI provider.');
      return;
    }

    const meta = getProviderMetadata(provider);
    const apiKey = meta?.requiresApiKey ? getAPIKey(provider) : '';
    const chosenModel = model;

    if (meta?.requiresApiKey && !apiKey) {
      setError('API key not configured. Please configure it in settings.');
      setShowSettings(true);
      return;
    }

    setIsAnalyzing(true);
    setError(null);

    try {
      // Format data for LLM
      const formatted = formatDataForLLM(sigmaMatches, data);
      setLastFormattedPrompt({ systemPrompt: formatted.systemPrompt, userPrompt: formatted.userPrompt });

      // Generate the three .txt files
      const files = [
        {
          name: 'DATASET SUMMARY.txt',
          content: formatted.attachments.datasetSummary,
        },
        {
          name: 'SIGMA DETECTIONS.txt',
          content: formatted.attachments.sigmaDetections,
        },
        {
          name: 'TIMELINE SUMMARY.txt',
          content: formatted.attachments.timelineSummary,
        },
      ];

      // Create simplified user prompt for file-based analysis
      const fileBasedUserPrompt = `Analyze the three attached files and provide comprehensive security insights and recommendations.`;

      // For providers that require endpoint (like Ollama), get it from stored apiKey
      const endpoint = meta?.requiresEndpoint ? getAPIKey(provider) : undefined;

      // Send to LLM with files (system prompt only, user prompt is minimal)
      const response = await sendAnalysisRequestWithFiles(
        provider,
        {
          apiKey: apiKey || '',
          model: chosenModel || '',
          temperature: 0.7,
          maxTokens: maxTokens || 4000,
          endpoint: endpoint || undefined,
        },
        files,
        formatted.systemPrompt,
        fileBasedUserPrompt
      );

      setAnalysisResult(response.content);
      setConversationHistory([
        { role: 'assistant', content: response.content }
      ]);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to analyze with file attachments';
      console.error('LLM Analysis Error (with files):', err);

      // Provide more helpful error messages
      let userFriendlyError = errorMessage;
      if (errorMessage.includes('401') || errorMessage.includes('Invalid API key')) {
        userFriendlyError = 'Invalid API key. Please check your API key in settings and try again.';
      } else if (errorMessage.includes('429') || errorMessage.includes('Rate limit')) {
        userFriendlyError = 'Rate limit exceeded. Please wait a moment and try again, or try a different provider.';
      } else if (errorMessage.includes('400') || errorMessage.includes('Bad request')) {
        userFriendlyError = `Invalid request: ${errorMessage}. Try selecting a different model.`;
      }

      setError(userFriendlyError);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleCopyResult = () => {
    if (analysisResult) {
      navigator.clipboard.writeText(analysisResult);
      // Show temporary feedback
      const button = document.querySelector('.copy-button') as HTMLElement;
      if (button) {
        const originalText = button.textContent;
        button.textContent = 'Copied!';
        setTimeout(() => {
          if (button) button.textContent = originalText;
        }, 2000);
      }
    }
  };

  const handleExportResult = () => {
    if (analysisResult) {
      const blob = new Blob([analysisResult], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `lumen-analysis-${new Date().toISOString()}.txt`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }
  };

  const handleClearConversation = () => {
    if (confirm('Are you sure you want to clear the conversation history? This cannot be undone.')) {
      setConversationHistory([]);
      clearConversation();
    }
  };

  const meta = getProviderMetadata(provider);
  const hasApiKey = meta?.requiresApiKey ? getAPIKey(provider) !== null : true;

  return (
    <div className="llm-analysis-page">
      <header className="llm-analysis-header">
        <div>
          <h1>AI Security Analysis</h1>
          <p className="llm-subtitle">
            Get AI-powered threat analysis and recommendations
          </p>
        </div>
        <button className="back-button" onClick={onBack}>
          ← Back to Analysis
        </button>
      </header>

      <div className="llm-analysis-content">
        {/* Configuration Panel */}
        <div className="llm-config-panel">
          <h3>Configuration</h3>
          
          <div className="config-row">
            <label>Provider</label>
            <select
              value={provider}
              onChange={(e) => {
                setProvider(e.target.value as LLMProvider);
                setModel(''); // Reset model when provider changes
              }}
              className="provider-select"
            >
              {getAllProviderMetadata().map(meta => (
                <option key={meta.id} value={meta.id}>
                  {meta.name}
                </option>
              ))}
            </select>
            {(() => {
              const meta = getProviderMetadata(provider);
              return meta && (
                <p className="help-text" style={{ marginTop: '0.5rem', fontSize: '0.85rem', color: '#999' }}>
                  {meta.description}
                </p>
              );
            })()}
          </div>

          {availableModels.length > 0 && (
            <>
              <div className="config-row">
                <label>Model</label>
                <select
                  value={model || ''}
                  onChange={(e) => setModel(e.target.value)}
                  className="model-select"
                >
                  {availableModels.map(m => (
                    <option key={m} value={m}>{m}</option>
                  ))}
                </select>
              </div>
          <div className="config-row">
            <label>Max completion tokens (size of AI response)</label>
            <input
              type="number"
              min={256}
              max={8000}
              value={maxTokens}
              onChange={(e) => setMaxTokens(parseInt(e.target.value, 10) || 0)}
              className="model-select"
              placeholder="e.g., 4000"
            />
            <p className="help-text" style={{ marginTop: '0.5rem', fontSize: '0.85rem', color: '#999' }}>
              Larger values allow longer explanations but increase cost/time. Try using at least 4000 tokens.
            </p>
          </div>
        </>
      )}

          <div className="config-row">
            <label>
              API Key Status
              {hasApiKey ? (
                <span className="status-badge valid">✓ Configured</span>
              ) : (
                <span className="status-badge invalid">✗ Not Configured</span>
              )}
            </label>
            <button
              onClick={() => setShowSettings(!showSettings)}
              className="configure-api-button"
              style={{ width: '100%', marginTop: '0.5rem' }}
            >
              {showSettings ? 'Hide Settings' : 'Configure API Key'}
            </button>
          </div>

          {showSettings && (
            <LLMSettings
              onClose={() => setShowSettings(false)}
              onConfigChange={() => {
                // Refresh state after config change
                setShowSettings(false);
                // Trigger model reload by incrementing counter
                setConfigChangeCounter(prev => prev + 1);
              }}
            />
          )}

          <div className="config-row">
            <button
              onClick={() => {
                const formatted = formatDataForLLM(sigmaMatches, data);
                setLastFormattedPrompt({ systemPrompt: formatted.systemPrompt, userPrompt: formatted.userPrompt });
                setFormattedPrompt(formatted);
                setShowPromptPreview(true);
              }}
              className="preview-prompt-button"
              style={{
                padding: '0.5rem 1rem',
                background: 'rgba(156, 163, 175, 0.1)',
                border: '1px solid #9ca3af',
                color: '#e5e7eb',
                borderRadius: '6px',
                cursor: 'pointer',
                fontSize: '0.9rem',
                marginBottom: '1rem',
              }}
            >
              Preview Prompt
            </button>
          </div>

          {provider === 'openai' ? (
            <button
              onClick={handleAnalyzeWithFiles}
              disabled={isAnalyzing || !hasApiKey || !hasSigmaAnalysis}
              className="analyze-button"
              title={
                !hasSigmaAnalysis
                  ? "Please perform SIGMA analysis first"
                  : !hasApiKey
                  ? "Please configure your API key"
                  : "Upload analysis data as PDF files"
              }
            >
              {isAnalyzing ? 'Uploading files...' : '📎 Analyze with AI (PDF Upload)'}
            </button>
          ) : (
            <button
              onClick={handleAnalyze}
              disabled={isAnalyzing || !hasApiKey || !hasSigmaAnalysis}
              className="analyze-button"
              title={
                !hasSigmaAnalysis
                  ? "Please perform SIGMA analysis first"
                  : !hasApiKey
                  ? "Please configure your API key"
                  : "Analyze with AI (inline prompt)"
              }
            >
              {isAnalyzing ? 'Analyzing...' : 'Analyze with AI'}
            </button>
          )}
        </div>

        {/* Results Panel */}
        <div className="llm-results-panel">
          {error && conversationHistory.length === 0 && (
            <div className="error-state">
              <h3>Error</h3>
              <p>{error}</p>
              <button onClick={() => setError(null)} className="dismiss-button">
                Dismiss
              </button>
            </div>
          )}

        {(conversationHistory.length > 0 || isAnalyzing) && (
          <div className="analysis-result">
            <div className="result-header">
              <h3>Analysis Conversation</h3>
              <div className="result-actions">
                  <div className="view-mode-toggle">
                    <button
                      onClick={() => setViewMode('formatted')}
                      className={`view-mode-button ${viewMode === 'formatted' ? 'active' : ''}`}
                      title="Formatted Markdown View"
                    >
                      📄 Formatted
                    </button>
                    <button
                      onClick={() => setViewMode('raw')}
                      className={`view-mode-button ${viewMode === 'raw' ? 'active' : ''}`}
                      title="Raw Markdown View"
                    >
                      📝 Raw
                    </button>
                  </div>
                  <button onClick={handleCopyResult} className="action-button copy-button">
                    📋 Copy {viewMode === 'raw' ? 'Markdown' : 'Text'}
                  </button>
                  <button onClick={handleExportResult} className="action-button">
                    💾 Export
                  </button>
                  <button onClick={handleClearConversation} className="action-button clear-button" title="Clear conversation history">
                    🗑️ Clear
                  </button>
                </div>
              </div>
              <div className="result-content conversation-view">
                {conversationHistory.map((message, idx) => (
                  <div key={idx} className={`message-block ${message.role}`}>
                    <div className="message-header">
                      <strong>{message.role === 'user' ? '👤 You' : '🤖 AI Assistant'}</strong>
                    </div>
                    <div className="message-content">
                      {viewMode === 'formatted' ? (
                        <div className="markdown-content">
                          <ReactMarkdown>{message.content}</ReactMarkdown>
                        </div>
                      ) : (
                        <pre className="raw-markdown">{message.content}</pre>
                      )}
                    </div>
                  </div>
                ))}

                {/* Loading indicator in conversation */}
                {isAnalyzing && (
                  <div className="message-block assistant loading">
                    <div className="message-header">
                      <strong>🤖 AI Assistant</strong>
                    </div>
                    <div className="message-content">
                      <div className="typing-indicator">
                        <span></span>
                        <span></span>
                        <span></span>
                      </div>
                      <p className="loading-text">Analyzing...</p>
                    </div>
                  </div>
                )}

                {/* Invisible element to scroll to */}
                <div ref={conversationEndRef} />
              </div>

              {/* Error message in conversation */}
              {error && conversationHistory.length > 0 && (
                <div className="conversation-error">
                  <span className="error-icon">⚠️</span>
                  <span className="error-message">{error}</span>
                  <button onClick={() => setError(null)} className="error-dismiss">×</button>
                </div>
              )}

              {/* Follow-up conversation input */}
              <div className="followup-panel">
                <textarea
                  value={followUpInput}
                  onChange={(e) => setFollowUpInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && !e.shiftKey) {
                      e.preventDefault();
                      if (!isAnalyzing && followUpInput.trim() && hasApiKey && conversationHistory.length > 0) {
                        // Trigger the send button click
                        document.querySelector<HTMLButtonElement>('.followup-actions .analyze-button')?.click();
                      }
                    }
                  }}
                  placeholder="Ask a follow-up question or request clarification... (Press Enter to send, Shift+Enter for new line)"
                  rows={3}
                  className="custom-prompt-input"
                />
                <div className="followup-actions">
                  <button
                    className="analyze-button"
                    disabled={isAnalyzing || !followUpInput.trim() || !hasApiKey}
                    onClick={async () => {
                      if (conversationHistory.length === 0) return;
                      const userQuestion = followUpInput.trim();
                      if (!userQuestion) return;

                      setIsAnalyzing(true);
                      setError(null);

                      // Add user question immediately to show in UI
                      setConversationHistory((prev) => [
                        ...prev,
                        { role: 'user', content: userQuestion }
                      ]);
                      setFollowUpInput('');

                      try {
                        const meta = getProviderMetadata(provider);
                        const apiKey = meta?.requiresApiKey ? getAPIKey(provider) : '';
                        if (meta?.requiresApiKey && !apiKey) {
                          setError('API key not configured. Please configure it in settings.');
                          setShowSettings(true);
                          setIsAnalyzing(false);
                          return;
                        }

                        // Build a compact follow-up prompt using history
                        const previousMessages = conversationHistory.map(msg =>
                          `${msg.role === 'user' ? 'User' : 'Assistant'}: ${msg.content}`
                        ).join('\n\n');
                        const followUpPrompt = `Previous conversation:\n${previousMessages}\n\nUser follow-up:\n${userQuestion}`;

                        const response = await sendAnalysisRequest(
                          provider,
                          {
                            apiKey: apiKey || '',
                            model: model || '',
                            temperature: 0.7,
                            maxTokens: maxTokens || 4000
                          },
                          // keep system prompt fixed
                          lastFormattedPrompt?.systemPrompt || formattedPrompt?.systemPrompt || '',
                          followUpPrompt
                        );

                        // Add AI response to conversation
                        setConversationHistory((prev) => [
                          ...prev,
                          { role: 'assistant', content: response.content }
                        ]);
                        setAnalysisResult(response.content);
                      } catch (err) {
                        const errorMessage = err instanceof Error ? err.message : 'Failed to send follow-up';
                        setError(errorMessage);
                      } finally {
                        setIsAnalyzing(false);
                      }
                    }}
                  >
                    {isAnalyzing ? 'Sending...' : 'Send follow-up'}
                  </button>
                </div>
              </div>
            </div>
          )}

          {!isAnalyzing && conversationHistory.length === 0 && !error && (
            <div className="empty-state">
              <div className="empty-icon">🤖</div>
              {!hasSigmaAnalysis ? (
                <>
                  <h3>SIGMA Analysis Required</h3>
                  <p>Before using AI analysis, you must first perform SIGMA detection on your logs.</p>
                  <p className="empty-note">
                    <strong>⚠️ Pre-requisite:</strong> Navigate to "SIGMA Detection" from the Analysis Selector
                    to scan your logs for threats and suspicious patterns. Once SIGMA analysis is complete,
                    you can return here to get AI-powered insights.
                  </p>
                  <button
                    onClick={onBack}
                    className="back-button"
                    style={{
                      marginTop: '1rem',
                      padding: '0.75rem 1.5rem',
                      background: '#2563eb',
                      color: 'white',
                      border: 'none',
                      borderRadius: '6px',
                      cursor: 'pointer',
                      fontSize: '1rem',
                      fontWeight: '600'
                    }}
                  >
                    ← Back to Analysis Selector
                  </button>
                </>
              ) : (
                <>
                  <h3>Ready for Analysis</h3>
                  <p>Configure your API key and click "Analyze with AI" to get started.</p>
                  <p className="empty-note">
                    The AI will analyze your SIGMA detections, timeline, and event data
                    to provide comprehensive security insights and recommendations.
                  </p>
                </>
              )}
            </div>
          )}
        </div>
      </div>

      {showPromptPreview && formattedPrompt && (
        <div className="prompt-preview-overlay" onClick={() => setShowPromptPreview(false)}>
          <div className="prompt-preview-modal" onClick={(e) => e.stopPropagation()}>
            <div className="prompt-preview-header">
              <h3>Full Prompt Preview</h3>
              <button className="close-button" onClick={() => setShowPromptPreview(false)}>x</button>
            </div>
            <div className="prompt-preview-content">
              <div className="prompt-section">
                <h4>System Prompt (DFIR Expert Context):</h4>
                <pre className="prompt-text">{formattedPrompt.systemPrompt}</pre>
              </div>

              {provider === 'openai' && (
                <div className="prompt-section" style={{ marginTop: '1.5rem', paddingTop: '1rem', borderTop: '2px solid rgba(59, 130, 246, 0.3)' }}>
                  <h4 style={{ color: '#3b82f6' }}>📎 File Attachments (PDF Documents):</h4>
                  <p style={{ fontSize: '0.9rem', color: '#9ca3af', marginBottom: '1rem' }}>
                    All analysis data is sent as 3 PDF file attachments to OpenAI Files API:
                  </p>
                  <div style={{ marginBottom: '1rem' }}>
                    <h5 style={{ fontSize: '0.95rem', color: '#93c5fd', marginBottom: '0.5rem' }}>📄 DATASET SUMMARY.txt:</h5>
                    <pre className="prompt-text" style={{ maxHeight: '200px', overflow: 'auto' }}>{(formattedPrompt as any).attachments?.datasetSummary || 'N/A'}</pre>
                  </div>
                  <div style={{ marginBottom: '1rem' }}>
                    <h5 style={{ fontSize: '0.95rem', color: '#93c5fd', marginBottom: '0.5rem' }}>📄 SIGMA DETECTIONS.txt:</h5>
                    <pre className="prompt-text" style={{ maxHeight: '200px', overflow: 'auto' }}>{(formattedPrompt as any).attachments?.sigmaDetections || 'N/A'}</pre>
                  </div>
                  <div style={{ marginBottom: '1rem' }}>
                    <h5 style={{ fontSize: '0.95rem', color: '#93c5fd', marginBottom: '0.5rem' }}>📄 TIMELINE SUMMARY.txt:</h5>
                    <pre className="prompt-text" style={{ maxHeight: '200px', overflow: 'auto' }}>{(formattedPrompt as any).attachments?.timelineSummary || 'N/A'}</pre>
                  </div>
                  <p style={{ fontSize: '0.85rem', color: '#86efac', fontStyle: 'italic' }}>
                    ✓ Only the system prompt and a minimal user prompt are sent as text. All data is in the attached files.
                  </p>
                </div>
              )}
              <div className="prompt-preview-actions">
                <button
                  onClick={() => {
                    let fullPrompt = `SYSTEM PROMPT:\n\n${formattedPrompt.systemPrompt}`;

                    if (provider === 'openai' && (formattedPrompt as any).attachments) {
                      fullPrompt += `\n\n\nFILE ATTACHMENTS:\n\n`;
                      fullPrompt += `=== DATASET SUMMARY.pdf ===\n${(formattedPrompt as any).attachments.datasetSummary}\n\n`;
                      fullPrompt += `=== SIGMA DETECTIONS.pdf ===\n${(formattedPrompt as any).attachments.sigmaDetections}\n\n`;
                      fullPrompt += `=== TIMELINE SUMMARY.pdf ===\n${(formattedPrompt as any).attachments.timelineSummary}`;
                    } else {
                      fullPrompt += `\n\n\nUSER PROMPT:\n\n${formattedPrompt.userPrompt}`;
                    }

                    navigator.clipboard.writeText(fullPrompt);
                    alert('Full prompt copied to clipboard!');
                  }}
                  className="copy-prompt-button"
                >
                  Copy Full Prompt
                </button>
                <button
                  onClick={() => setShowPromptPreview(false)}
                  className="close-prompt-button"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
