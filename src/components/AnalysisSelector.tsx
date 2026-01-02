import { useState, useEffect } from 'react';
import { ParsedData } from '../types';
import { SigmaRuleMatch } from '../lib/sigma/types';
import ExportReport from './ExportReport';
import './AnalysisSelector.css';

export type AnalysisMode =
  | 'sigma'
  | 'dashboards'
  | 'process-analysis'
  | 'timeline'
  | 'raw-logs'
  | 'ioc-extraction'
  | 'event-correlation'
  | 'ai-analysis';

interface AnalysisSelectorProps {
  data: ParsedData;
  filename: string;
  onSelect: (mode: AnalysisMode) => void;
  onReset: () => void;
  onOpenSessions?: () => void;
  sigmaMatches?: Map<string, SigmaRuleMatch[]>;
  platform?: string | null;
}

export default function AnalysisSelector({
  data,
  filename,
  onSelect,
  onReset,
  onOpenSessions,
  sigmaMatches = new Map(),
  platform = null
}: AnalysisSelectorProps) {
  const [hoveredCard, setHoveredCard] = useState<string | null>(null);
  const [showExportReport, setShowExportReport] = useState(false);
  const [sigmaAnalyzed, setSigmaAnalyzed] = useState(false);
  const [dismissedBanner, setDismissedBanner] = useState(false);

  const isEvtx = data.format === 'evtx';

  // Check if SIGMA has been analyzed (has any results)
  const hasSigmaResults = sigmaMatches.size > 0;

  // Update sigmaAnalyzed when we have results
  useEffect(() => {
    if (hasSigmaResults) {
      setSigmaAnalyzed(true);
    }
  }, [hasSigmaResults]);

  // Show the "Start with SIGMA" banner if:
  // - SIGMA hasn't been analyzed yet in this session
  // - User hasn't dismissed the banner
  const showSigmaBanner = !sigmaAnalyzed && !dismissedBanner;

  // Handle SIGMA card click
  const handleSigmaClick = () => {
    setSigmaAnalyzed(true);
    onSelect('sigma');
  };

  return (
    <div className="analysis-selector">
      <div className="selector-header">
        <div className="header-content">
          <div className="logo-container">
            <h1>LUMEN</h1>
            <span className="logo-icon">🔆</span>
          </div>
          <p className="tagline">Your EVTX companion</p>
        </div>
        <div className="header-actions">
          <button className="export-button" onClick={() => setShowExportReport(true)}>
            Export Report
          </button>
          {onOpenSessions && (
            <button className="sessions-button" onClick={onOpenSessions}>
              Sessions
            </button>
          )}
          <button className="reset-button" onClick={onReset}>
            ← Upload Different File
          </button>
        </div>
      </div>

      <div className="file-info">
        <div className="file-badge">
          <span className="file-icon">📄</span>
          <span className="file-name">{filename}</span>
        </div>
        <div className="file-stats">
          <span className="stat">
            <strong>{data.entries.length.toLocaleString()}</strong> events
          </span>
          <span className="stat">
            <strong>{data.format.toUpperCase()}</strong> format
          </span>
          {isEvtx && (
            <span className="stat">
              <strong>{new Set(data.entries.map(e => e.eventId)).size}</strong> unique event IDs
            </span>
          )}
        </div>
      </div>



      {/* SIGMA First Banner */}
      {showSigmaBanner && (
        <div className="sigma-first-banner">
          <div className="banner-content">
            <div className="banner-icon">🛡️</div>
            <div className="banner-text">
              <h3>Start with SIGMA Detection</h3>
              <p>For best results, run SIGMA threat detection first. Other analysis features like Timeline and Event Correlation rely on SIGMA results.</p>
            </div>
            <button className="banner-dismiss" onClick={() => setDismissedBanner(true)} aria-label="Dismiss">×</button>
          </div>
          <button className="banner-cta" onClick={handleSigmaClick}>
            Run SIGMA Analysis →
          </button>
        </div>
      )}

      <h2 className="section-title">Select Analysis Type</h2>

      <div className="analysis-cards">
        {/* SIGMA Detection */}
        <div
          className={`analysis-card sigma ${hoveredCard === 'sigma' ? 'hovered' : ''} ${showSigmaBanner ? 'recommended' : ''}`}
          onClick={handleSigmaClick}
          onMouseEnter={() => setHoveredCard('sigma')}
          onMouseLeave={() => setHoveredCard(null)}
        >
          {showSigmaBanner && <div className="recommended-badge">Recommended First</div>}
          <div className="card-icon">🛡️</div>
          <div className="card-content">
            <h3>SIGMA Detection</h3>
            <p>Detect threats using SIGMA rules. Identify malicious patterns, suspicious behaviors, and security incidents in your logs.</p>
          </div>
          <div className="card-arrow">→</div>
        </div>

        {/* Dashboards & Metrics */}
        <div
          className={`analysis-card dashboards ${hoveredCard === 'dashboards' ? 'hovered' : ''}`}
          onClick={() => onSelect('dashboards')}
          onMouseEnter={() => setHoveredCard('dashboards')}
          onMouseLeave={() => setHoveredCard(null)}
        >
          <div className="card-icon">📊</div>
          <div className="card-content">
            <h3>Dashboards & Metrics</h3>
            <p>Visualize log data with interactive charts. View event distributions, time series, and aggregated statistics.</p>
          </div>
          <div className="card-arrow">→</div>
        </div>

        {/* Process Analysis - only for EVTX */}
        {isEvtx && (
          <div
            className={`analysis-card process ${hoveredCard === 'process' ? 'hovered' : ''}`}
            onClick={() => onSelect('process-analysis')}
            onMouseEnter={() => setHoveredCard('process')}
            onMouseLeave={() => setHoveredCard(null)}
          >
            <div className="card-icon">⚙️</div>
            <div className="card-content">
              <h3>Process Execution Analysis</h3>
              <p>Analyze process creation events. Identify suspicious executions, parent-child relationships, and unusual locations.</p>
            </div>
            <div className="card-arrow">→</div>
          </div>
        )}

        {/* Timeline View - only for EVTX with SIGMA */}
        {isEvtx && (
          <div
            className={`analysis-card timeline ${hoveredCard === 'timeline' ? 'hovered' : ''}`}
            onClick={() => onSelect('timeline')}
            onMouseEnter={() => setHoveredCard('timeline')}
            onMouseLeave={() => setHoveredCard(null)}
          >
            <div className="card-icon">📅</div>
            <div className="card-content">
              <h3>Threat Timeline</h3>
              <p>View SIGMA detections on a timeline. Understand the sequence of security events and investigate incident progression.</p>
            </div>
            <div className="card-arrow">→</div>
          </div>
        )}

        {/* Event Correlation - only for EVTX */}
        {isEvtx && (
          <div
            className={`analysis-card correlation ${hoveredCard === 'correlation' ? 'hovered' : ''}`}
            onClick={() => onSelect('event-correlation')}
            onMouseEnter={() => setHoveredCard('correlation')}
            onMouseLeave={() => setHoveredCard(null)}
          >
            <div className="card-icon">🔗</div>
            <div className="card-content">
              <h3>Event Correlation</h3>
              <p>Build chains of related events. Identify attack patterns, process relationships, and correlated activities across logs.</p>
            </div>
            <div className="card-arrow">→</div>
          </div>
        )}

        {/* IOC Extraction */}
        <div
          className={`analysis-card ioc ${hoveredCard === 'ioc' ? 'hovered' : ''}`}
          onClick={() => onSelect('ioc-extraction')}
          onMouseEnter={() => setHoveredCard('ioc')}
          onMouseLeave={() => setHoveredCard(null)}
        >
          <div className="card-icon">🎯</div>
          <div className="card-content">
            <h3>IOC Extraction</h3>
            <p>Extract Indicators of Compromise from logs. Find IPs, domains, file hashes, paths, URLs, and email addresses.</p>
          </div>
          <div className="card-arrow">→</div>
        </div>

        {/* Raw Logs */}
        <div
          className={`analysis-card raw-logs ${hoveredCard === 'raw-logs' ? 'hovered' : ''}`}
          onClick={() => onSelect('raw-logs')}
          onMouseEnter={() => setHoveredCard('raw-logs')}
          onMouseLeave={() => setHoveredCard(null)}
        >
          <div className="card-icon">📋</div>
          <div className="card-content">
            <h3>Raw Logs Explorer</h3>
            <p>Browse and filter all log entries. Search by timestamp, event ID, computer, source, or message content.</p>
          </div>
          <div className="card-arrow">→</div>
        </div>

        {/* AI Analysis */}
        <div
          className={`analysis-card ai ${hoveredCard === 'ai' ? 'hovered' : ''}`}
          onClick={() => onSelect('ai-analysis')}
          onMouseEnter={() => setHoveredCard('ai')}
          onMouseLeave={() => setHoveredCard(null)}
        >
          <div className="card-icon">🤖</div>
          <div className="card-content">
            <h3>AI-Powered Analysis</h3>
            <p>Let AI analyze your logs, identify anomalies, and provide natural language insights about security events.</p>
          </div>
          <div className="card-arrow">→</div>
        </div>

        {/* GitHub Link */}
        <a
          href="https://github.com/Koifman/LUMEN"
          target="_blank"
          rel="noopener noreferrer"
          className={`analysis-card feedback ${hoveredCard === 'feedback' ? 'hovered' : ''}`}
          onMouseEnter={() => setHoveredCard('feedback')}
          onMouseLeave={() => setHoveredCard(null)}
        >
          <div className="card-icon">💬</div>
          <div className="card-content">
            <h3>Submit Bugs/Features</h3>
            <p>Report bugs, request features, or provide feedback on GitHub.</p>
          </div>
          <div className="card-arrow">→</div>
        </a>

        {/* Support Button */}
        <a
          href="https://ko-fi.com/koifsec"
          target="_blank"
          rel="noopener noreferrer"
          className={`analysis-card support ${hoveredCard === 'support' ? 'hovered' : ''}`}
          onMouseEnter={() => setHoveredCard('support')}
          onMouseLeave={() => setHoveredCard(null)}
        >
          <div className="card-icon">☕</div>
          <div className="card-content">
            <h3>Support Development</h3>
            <p>Buy me a coffee to support ongoing development and new features.</p>
          </div>
          <div className="card-arrow">→</div>
        </a>
      </div>

      <div className="privacy-note">
        All analysis is performed locally in your browser. No data leaves your machine (except when using AI features).
      </div>

      {/* Export Report Modal */}
      {showExportReport && (
        <ExportReport
          data={data}
          filename={filename}
          platform={platform}
          sigmaMatches={sigmaMatches}
          onClose={() => setShowExportReport(false)}
        />
      )}
    </div>
  );
}
