/**
 * SIGMA Rule Loader Component
 *
 * UI for loading SIGMA rules from YAML files
 */

import { useState, useCallback } from 'react';
import { SigmaEngine } from '../lib/sigma';
import { loadRulesFromFiles, getRuleSummary } from '../lib/sigma/utils/ruleLoader';
import './SigmaRuleLoader.css';

interface SigmaRuleLoaderProps {
  engine: SigmaEngine;
  onRulesLoaded?: (count: number) => void;
}

export default function SigmaRuleLoader({ engine, onRulesLoaded }: SigmaRuleLoaderProps) {
  const [loading, setLoading] = useState(false);
  const [summary, setSummary] = useState<{
    loaded: number;
    failed: number;
    errors: { file: string; error: string }[];
  } | null>(null);
  const [isDragging, setIsDragging] = useState(false);

  const handleFiles = useCallback(async (files: File[]) => {
    if (files.length === 0) return;

    setLoading(true);
    setSummary(null);

    try {
      // Get summary first
      await getRuleSummary(files);

      // Load rules
      const result = await loadRulesFromFiles(engine, files);

      setSummary({
        loaded: result.loaded,
        failed: result.failed,
        errors: result.errors
      });

      if (onRulesLoaded && result.loaded > 0) {
        onRulesLoaded(result.loaded);
      }
    } catch (error) {
      setSummary({
        loaded: 0,
        failed: files.length,
        errors: [{
          file: 'all',
          error: error instanceof Error ? error.message : String(error)
        }]
      });
    } finally {
      setLoading(false);
    }
  }, [engine, onRulesLoaded]);

  const handleFileInput = useCallback((event: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(event.target.files || []);
    handleFiles(files);
  }, [handleFiles]);

  const handleDrop = useCallback((event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setIsDragging(false);

    const files = Array.from(event.dataTransfer.files).filter(
      file => file.name.endsWith('.yml') || file.name.endsWith('.yaml')
    );

    handleFiles(files);
  }, [handleFiles]);

  const handleDragOver = useCallback((event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback(() => {
    setIsDragging(false);
  }, []);

  return (
    <div className="sigma-rule-loader">
      <h3>📂 Load SIGMA Rules</h3>

      <div
        className={`sigma-drop-zone ${isDragging ? 'dragging' : ''}`}
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
      >
        <div className="sigma-drop-zone-content">
          <span className="drop-icon">📁</span>
          <p>Drop YAML rule files here</p>
          <p className="drop-hint">or</p>
          <label className="file-button">
            <input
              type="file"
              multiple
              accept=".yml,.yaml"
              onChange={handleFileInput}
              style={{ display: 'none' }}
            />
            Browse Files
          </label>
        </div>
      </div>

      {loading && (
        <div className="loading-status">
          <div className="spinner"></div>
          <span>Loading rules...</span>
        </div>
      )}

      {summary && (
        <div className="load-summary">
          {summary.loaded > 0 && (
            <div className="summary-success">
              ✅ Successfully loaded <strong>{summary.loaded}</strong> rules
            </div>
          )}

          {summary.failed > 0 && (
            <div className="summary-errors">
              <div className="error-header">
                ⚠️ Failed to load <strong>{summary.failed}</strong> file(s)
              </div>
              {summary.errors.length > 0 && (
                <details className="error-details">
                  <summary>Show errors</summary>
                  <ul>
                    {summary.errors.slice(0, 10).map((err, idx) => (
                      <li key={idx}>
                        <strong>{err.file}</strong>: {err.error}
                      </li>
                    ))}
                    {summary.errors.length > 10 && (
                      <li>... and {summary.errors.length - 10} more errors</li>
                    )}
                  </ul>
                </details>
              )}
            </div>
          )}
        </div>
      )}

      <div className="loader-info">
        <p>
          Load custom SIGMA rules in YAML format. You can select multiple files or an entire folder.
        </p>
        <p className="hint">
          💡 <strong>Popular rule sources:</strong>
        </p>
        <ul style={{ marginTop: '0.5rem', paddingLeft: '1.5rem', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
          <li>
            <a
              href="https://github.com/WithSecureLabs/chainsaw/tree/master/sigma_rules"
              target="_blank"
              rel="noopener noreferrer"
            >
              Chainsaw SIGMA rules
            </a>{' '}
            - Windows-focused threat hunting rules
          </li>
          <li>
            <a
              href="https://github.com/SigmaHQ/sigma/tree/master/rules/windows"
              target="_blank"
              rel="noopener noreferrer"
            >
              SigmaHQ repository
            </a>{' '}
            - Official community-driven rules
          </li>
          <li>
            <a
              href="https://socprime.com/threat-detection-marketplace/"
              target="_blank"
              rel="noopener noreferrer"
            >
              SOC Prime
            </a>{' '}
            - Commercial and free detection content
          </li>
        </ul>
      </div>
    </div>
  );
}
