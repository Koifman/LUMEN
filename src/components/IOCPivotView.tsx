import { useEffect, useState, useMemo, useRef } from 'react';
import { LogEntry } from '../types';
import { SigmaRuleMatch } from '../lib/sigma/types';
import { CorrelatedChain } from '../lib/correlationEngine';
import {
  IOCType,
  IOCSearchResult,
  IOCEventMatch,
  searchIOCInEvents,
  findChainsContainingIOC,
  getIOCTypeLabel,
  getIOCTypeIcon,
} from '../lib/iocSearchEngine';
import { getFileColor, getFileBgColor } from '../lib/fileColors';
import './IOCPivotView.css';

interface IOCPivotViewProps {
  ioc: string;
  type: IOCType;
  entries: LogEntry[];
  sigmaMatches: Map<string, SigmaRuleMatch[]>;
  correlationChains?: CorrelatedChain[];
  onClose: () => void;
  onNavigateToChain?: (chainId: string) => void;
}

type TabType = 'all' | 'byFile' | 'byType' | 'chains';

export function IOCPivotView({
  ioc,
  type,
  entries,
  sigmaMatches,
  correlationChains,
  onClose,
  onNavigateToChain,
}: IOCPivotViewProps) {
  const modalRef = useRef<HTMLDivElement>(null);
  const [activeTab, setActiveTab] = useState<TabType>('all');
  const [isSearching, setIsSearching] = useState(true);
  const [selectedEventMatch, setSelectedEventMatch] = useState<IOCEventMatch | null>(null);
  const [expandedFile, setExpandedFile] = useState<string | null>(null);
  const [expandedType, setExpandedType] = useState<string | null>(null);

  // Perform the search
  const searchResult = useMemo<IOCSearchResult | null>(() => {
    setIsSearching(true);
    try {
      const result = searchIOCInEvents(ioc, type, entries, sigmaMatches);

      // Add correlation chain info if available
      if (correlationChains && correlationChains.length > 0) {
        result.relatedChainIds = findChainsContainingIOC(ioc, type, correlationChains);
      }

      return result;
    } finally {
      setIsSearching(false);
    }
  }, [ioc, type, entries, sigmaMatches, correlationChains]);

  // Handle ESC key to close modal
  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        if (selectedEventMatch) {
          setSelectedEventMatch(null);
        } else {
          onClose();
        }
      }
    };

    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, [onClose, selectedEventMatch]);

  // Prevent body scroll when modal is open
  useEffect(() => {
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = '';
    };
  }, []);

  // Handle click outside modal to close
  const handleBackdropClick = (e: React.MouseEvent) => {
    if (e.target === e.currentTarget) {
      onClose();
    }
  };

  // Format timestamp for display
  const formatTimestamp = (timestamp: Date | string | undefined): string => {
    if (!timestamp) return 'Unknown';
    const date = new Date(timestamp);
    return date.toLocaleString();
  };

  // Render stats bar
  const renderStatsBar = () => {
    if (!searchResult) return null;

    const fileCount = searchResult.eventsByFile.size;
    const sigmaCount = searchResult.events.filter(e => e.hasSigmaMatch).length;
    const chainCount = searchResult.relatedChainIds.length;

    return (
      <div className="pivot-stats-bar">
        <div className="pivot-stat">
          <span className="pivot-stat-value">{searchResult.totalMatches}</span>
          <span className="pivot-stat-label">Events</span>
        </div>
        <div className="pivot-stat">
          <span className="pivot-stat-value">{fileCount}</span>
          <span className="pivot-stat-label">Files</span>
        </div>
        <div className="pivot-stat">
          <span className="pivot-stat-value">{sigmaCount}</span>
          <span className="pivot-stat-label">SIGMA Hits</span>
        </div>
        {correlationChains && (
          <div className="pivot-stat">
            <span className="pivot-stat-value">{chainCount}</span>
            <span className="pivot-stat-label">Chains</span>
          </div>
        )}
        {searchResult.firstSeen && searchResult.lastSeen && (
          <div className="pivot-stat pivot-stat-time">
            <span className="pivot-stat-value">
              {formatTimestamp(searchResult.firstSeen)} - {formatTimestamp(searchResult.lastSeen)}
            </span>
            <span className="pivot-stat-label">Time Range</span>
          </div>
        )}
      </div>
    );
  };

  // Render a single event row
  const renderEventRow = (eventMatch: IOCEventMatch, index: number) => {
    const { event, matchedFields, hasSigmaMatch, sigmaRules } = eventMatch;

    return (
      <div
        key={index}
        className={`pivot-event-row ${hasSigmaMatch ? 'has-sigma' : ''}`}
        onClick={() => setSelectedEventMatch(eventMatch)}
      >
        <div className="pivot-event-main">
          <span className="pivot-event-time">
            {formatTimestamp(event.timestamp)}
          </span>
          <span className="pivot-event-id">
            Event {event.eventId || '?'}
          </span>
          <span className="pivot-event-computer">
            {event.computer || 'Unknown'}
          </span>
          {event.sourceFile && (
            <span
              className="pivot-event-file"
              style={{
                backgroundColor: getFileBgColor(event.sourceFile),
                borderColor: getFileColor(event.sourceFile),
              }}
            >
              {event.sourceFile}
            </span>
          )}
        </div>
        <div className="pivot-event-meta">
          <span className="pivot-event-fields" title={`Found in: ${matchedFields.join(', ')}`}>
            Fields: {matchedFields.slice(0, 3).join(', ')}
            {matchedFields.length > 3 && ` +${matchedFields.length - 3}`}
          </span>
          {hasSigmaMatch && (
            <span className="pivot-sigma-badge" title={sigmaRules?.join(', ')}>
              SIGMA
            </span>
          )}
        </div>
      </div>
    );
  };

  // Render "All Events" tab
  const renderAllEvents = () => {
    if (!searchResult) return null;

    const events = searchResult.events;
    const displayLimit = 100;

    return (
      <div className="pivot-events-list">
        {events.slice(0, displayLimit).map((eventMatch, idx) => renderEventRow(eventMatch, idx))}
        {events.length > displayLimit && (
          <div className="pivot-more-events">
            +{events.length - displayLimit} more events
          </div>
        )}
        {events.length === 0 && (
          <div className="pivot-no-events">
            No events found containing this IOC
          </div>
        )}
      </div>
    );
  };

  // Render "By File" tab
  const renderByFile = () => {
    if (!searchResult) return null;

    const fileEntries = Array.from(searchResult.eventsByFile.entries())
      .sort((a, b) => b[1].length - a[1].length);

    return (
      <div className="pivot-grouped-list">
        {fileEntries.map(([file, events]) => (
          <div key={file} className="pivot-group">
            <div
              className="pivot-group-header"
              onClick={() => setExpandedFile(expandedFile === file ? null : file)}
              style={{
                borderLeftColor: getFileColor(file),
              }}
            >
              <span className="pivot-group-icon">{expandedFile === file ? '▼' : '▶'}</span>
              <span
                className="pivot-group-name"
                style={{ color: getFileColor(file) }}
              >
                {file}
              </span>
              <span className="pivot-group-count">{events.length} events</span>
              <span className="pivot-group-sigma">
                {events.filter(e => e.hasSigmaMatch).length} SIGMA
              </span>
            </div>
            {expandedFile === file && (
              <div className="pivot-group-events">
                {events.slice(0, 50).map((eventMatch, idx) => renderEventRow(eventMatch, idx))}
                {events.length > 50 && (
                  <div className="pivot-more-events">+{events.length - 50} more events</div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    );
  };

  // Render "By Event Type" tab
  const renderByType = () => {
    if (!searchResult) return null;

    const typeEntries = Array.from(searchResult.eventsByType.entries())
      .sort((a, b) => b[1].length - a[1].length);

    return (
      <div className="pivot-grouped-list">
        {typeEntries.map(([eventType, events]) => (
          <div key={eventType} className="pivot-group">
            <div
              className="pivot-group-header"
              onClick={() => setExpandedType(expandedType === eventType ? null : eventType)}
            >
              <span className="pivot-group-icon">{expandedType === eventType ? '▼' : '▶'}</span>
              <span className="pivot-group-name">{eventType}</span>
              <span className="pivot-group-count">{events.length} events</span>
              <span className="pivot-group-sigma">
                {events.filter(e => e.hasSigmaMatch).length} SIGMA
              </span>
            </div>
            {expandedType === eventType && (
              <div className="pivot-group-events">
                {events.slice(0, 50).map((eventMatch, idx) => renderEventRow(eventMatch, idx))}
                {events.length > 50 && (
                  <div className="pivot-more-events">+{events.length - 50} more events</div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    );
  };

  // Render "Chains" tab
  const renderChains = () => {
    if (!searchResult || !correlationChains) return null;

    const relatedChains = correlationChains.filter(chain =>
      searchResult.relatedChainIds.includes(chain.id)
    );

    if (relatedChains.length === 0) {
      return (
        <div className="pivot-no-chains">
          <p>No correlation chains contain events with this IOC.</p>
          <p className="pivot-no-chains-hint">
            Run SIGMA detection and Event Correlation first to see attack chains.
          </p>
        </div>
      );
    }

    return (
      <div className="pivot-chains-list">
        {relatedChains.map(chain => (
          <div
            key={chain.id}
            className={`pivot-chain-card pivot-chain-${chain.severity}`}
            onClick={() => onNavigateToChain?.(chain.id)}
          >
            <div className="pivot-chain-header">
              <span className={`pivot-chain-severity ${chain.severity}`}>
                {chain.severity.toUpperCase()}
              </span>
              <span className="pivot-chain-events">
                {chain.events.length} events
              </span>
              <span className="pivot-chain-score">
                Score: {chain.score}
              </span>
            </div>
            <div className="pivot-chain-summary">
              {chain.summary || 'No summary available'}
            </div>
            <div className="pivot-chain-meta">
              <span>Duration: {formatDuration(chain.duration)}</span>
              <span>SIGMA matches: {chain.sigmaMatches.length}</span>
            </div>
          </div>
        ))}
      </div>
    );
  };

  // Format duration in human-readable form
  const formatDuration = (ms: number): string => {
    if (ms < 1000) return `${ms}ms`;
    if (ms < 60000) return `${Math.round(ms / 1000)}s`;
    if (ms < 3600000) return `${Math.round(ms / 60000)}m`;
    return `${Math.round(ms / 3600000)}h`;
  };

  // Render timeline mini-chart
  const renderTimeline = () => {
    if (!searchResult || searchResult.timelineData.length === 0) return null;

    const maxCount = Math.max(...searchResult.timelineData.map(t => t.count));

    return (
      <div className="pivot-timeline">
        <div className="pivot-timeline-bars">
          {searchResult.timelineData.map((point, idx) => (
            <div
              key={idx}
              className="pivot-timeline-bar"
              style={{
                height: `${(point.count / maxCount) * 100}%`,
              }}
              title={`${point.hour}: ${point.count} events`}
            />
          ))}
        </div>
        <div className="pivot-timeline-labels">
          <span>{searchResult.timelineData[0]?.hour}</span>
          <span>{searchResult.timelineData[searchResult.timelineData.length - 1]?.hour}</span>
        </div>
      </div>
    );
  };

  return (
    <div className="pivot-modal-backdrop" onClick={handleBackdropClick}>
      <div className="pivot-modal" ref={modalRef}>
        {/* Header */}
        <div className="pivot-modal-header">
          <div className="pivot-header-content">
            <span className="pivot-type-icon">{getIOCTypeIcon(type)}</span>
            <div className="pivot-header-text">
              <h2 className="pivot-ioc-value" title={ioc}>
                {ioc.length > 60 ? ioc.substring(0, 60) + '...' : ioc}
              </h2>
              <span className="pivot-ioc-type">{getIOCTypeLabel(type)}</span>
            </div>
          </div>
          <button className="pivot-close-btn" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </div>

        {/* Stats */}
        {!isSearching && renderStatsBar()}

        {/* Timeline */}
        {!isSearching && searchResult && searchResult.timelineData.length > 1 && renderTimeline()}

        {/* Tabs */}
        <div className="pivot-tabs">
          <button
            className={`pivot-tab ${activeTab === 'all' ? 'active' : ''}`}
            onClick={() => setActiveTab('all')}
          >
            All Events
            {searchResult && <span className="pivot-tab-count">{searchResult.totalMatches}</span>}
          </button>
          <button
            className={`pivot-tab ${activeTab === 'byFile' ? 'active' : ''}`}
            onClick={() => setActiveTab('byFile')}
          >
            By File
            {searchResult && <span className="pivot-tab-count">{searchResult.eventsByFile.size}</span>}
          </button>
          <button
            className={`pivot-tab ${activeTab === 'byType' ? 'active' : ''}`}
            onClick={() => setActiveTab('byType')}
          >
            By Event Type
            {searchResult && <span className="pivot-tab-count">{searchResult.eventsByType.size}</span>}
          </button>
          {correlationChains && (
            <button
              className={`pivot-tab ${activeTab === 'chains' ? 'active' : ''}`}
              onClick={() => setActiveTab('chains')}
            >
              Chains
              {searchResult && (
                <span className="pivot-tab-count">{searchResult.relatedChainIds.length}</span>
              )}
            </button>
          )}
        </div>

        {/* Content */}
        <div className="pivot-content">
          {isSearching ? (
            <div className="pivot-loading">
              <div className="pivot-loading-spinner" />
              <span>Searching events...</span>
            </div>
          ) : (
            <>
              {activeTab === 'all' && renderAllEvents()}
              {activeTab === 'byFile' && renderByFile()}
              {activeTab === 'byType' && renderByType()}
              {activeTab === 'chains' && renderChains()}
            </>
          )}
        </div>

        {/* Footer */}
        <div className="pivot-modal-footer">
          <button className="pivot-btn-secondary" onClick={onClose}>
            Close
          </button>
        </div>
      </div>

      {/* Event Details Modal - Shows matched fields for SIGMA events, raw log otherwise */}
      {selectedEventMatch && (
        <div className="pivot-event-detail-backdrop" onClick={() => setSelectedEventMatch(null)}>
          <div className="pivot-event-detail-modal" onClick={e => e.stopPropagation()}>
            <div className="pivot-event-detail-header">
              <div className="pivot-event-detail-title">
                <h3>Event Details</h3>
                <span className="pivot-event-detail-meta">
                  Event {selectedEventMatch.event.eventId || '?'} | {formatTimestamp(selectedEventMatch.event.timestamp)}
                </span>
              </div>
              <button
                className="pivot-close-btn"
                onClick={() => setSelectedEventMatch(null)}
                aria-label="Close"
              >
                ✕
              </button>
            </div>

            <div className="pivot-event-detail-content">
              {/* IOC Match Info */}
              <div className="pivot-event-detail-section">
                <h4>IOC Match</h4>
                <div className="pivot-event-detail-ioc-info">
                  <span className="pivot-event-detail-label">IOC:</span>
                  <span className="pivot-event-detail-value">{ioc}</span>
                </div>
                <div className="pivot-event-detail-ioc-info">
                  <span className="pivot-event-detail-label">Found in fields:</span>
                  <span className="pivot-event-detail-value">{selectedEventMatch.matchedFields.join(', ')}</span>
                </div>
              </div>

              {/* SIGMA Matched Fields - Only if has SIGMA match */}
              {selectedEventMatch.hasSigmaMatch && selectedEventMatch.sigmaMatches && (
                <div className="pivot-event-detail-section pivot-sigma-section">
                  <h4>SIGMA Detection Details</h4>
                  {selectedEventMatch.sigmaMatches.map((match, matchIdx) => {
                    // Extract all matched fields from the SIGMA match
                    const allFieldMatches: Array<{
                      field: string;
                      value: any;
                      selection: string;
                      modifier?: string;
                      matchedPattern?: string | number | null | (string | number | null)[];
                    }> = [];

                    if (match.selectionMatches) {
                      for (const selMatch of match.selectionMatches) {
                        if (selMatch.fieldMatches) {
                          for (const fm of selMatch.fieldMatches) {
                            const isFilterSelection = selMatch.selection.toLowerCase().startsWith('filter');
                            if (!isFilterSelection && (fm.value === undefined || fm.value === null)) {
                              continue;
                            }
                            allFieldMatches.push({
                              field: fm.field,
                              value: fm.value,
                              selection: selMatch.selection,
                              modifier: fm.modifier,
                              matchedPattern: fm.matchedPattern
                            });
                          }
                        }
                      }
                    }

                    return (
                      <div key={matchIdx} className="pivot-sigma-match">
                        <div className="pivot-sigma-rule-header">
                          <span className={`pivot-sigma-level ${match.rule.level || 'medium'}`}>
                            {(match.rule.level || 'medium').toUpperCase()}
                          </span>
                          <span className="pivot-sigma-rule-title">{match.rule.title}</span>
                        </div>
                        {match.rule.description && (
                          <div className="pivot-sigma-description">{match.rule.description}</div>
                        )}
                        {allFieldMatches.length > 0 && (
                          <div className="pivot-matched-fields">
                            <div className="pivot-matched-fields-header">Matched Fields:</div>
                            {allFieldMatches.map((fm, fmIdx) => (
                              <div key={fmIdx} className="pivot-field-match">
                                <div className="pivot-field-header">
                                  <span className="pivot-field-name">{fm.field}</span>
                                  {fm.modifier && fm.modifier !== 'equals' && (
                                    <span className="pivot-field-modifier">|{fm.modifier}</span>
                                  )}
                                  {fm.selection.toLowerCase().startsWith('filter') && (
                                    <span className="pivot-field-not">NOT</span>
                                  )}
                                  <span className="pivot-field-selection">{fm.selection}</span>
                                </div>
                                <div className="pivot-field-value">
                                  {fm.value === undefined || fm.value === null
                                    ? <span className="pivot-field-empty">
                                        {fm.value === null ? '(null)' : '(not found)'}
                                      </span>
                                    : (fm.value === ''
                                      ? <span className="pivot-field-empty">(empty)</span>
                                      : String(fm.value).substring(0, 500) + (String(fm.value).length > 500 ? '...' : '')
                                    )
                                  }
                                </div>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}

              {/* Raw Event - Show for non-SIGMA events, or as additional info for SIGMA events */}
              <div className="pivot-event-detail-section">
                <h4>{selectedEventMatch.hasSigmaMatch ? 'Raw Event Data' : 'Event Data'}</h4>
                <pre className="pivot-event-raw">
                  {JSON.stringify(selectedEventMatch.event, null, 2)}
                </pre>
              </div>
            </div>

            <div className="pivot-event-detail-footer">
              <button
                className="pivot-btn-secondary"
                onClick={async () => {
                  try {
                    await navigator.clipboard.writeText(JSON.stringify(selectedEventMatch.event, null, 2));
                  } catch (err) {
                    console.error('Failed to copy:', err);
                  }
                }}
              >
                Copy Raw Event
              </button>
              <button className="pivot-btn-secondary" onClick={() => setSelectedEventMatch(null)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default IOCPivotView;
