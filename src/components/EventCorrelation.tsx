import { useState, useMemo, useEffect } from 'react';
import { LogEntry, ParsedData } from '../types';
import { SigmaRuleMatch } from '../lib/sigma/types';
import { correlateEvents, CorrelatedChain } from '../lib/correlationEngine';
import ExportReport from './ExportReport';
import './EventCorrelation.css';

interface EventCorrelationProps {
  entries: LogEntry[];
  sigmaMatches: Map<string, SigmaRuleMatch[]>;
  onBack: () => void;
  data: ParsedData;
  filename: string;
  platform: string | null;
}

export default function EventCorrelation({ entries, sigmaMatches, onBack, data, filename, platform }: EventCorrelationProps) {
  const [minEvents, setMinEvents] = useState(3);
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [showExportReport, setShowExportReport] = useState(false);
  const [viewMode, setViewMode] = useState<'chains' | 'story'>('chains');
  const [isCorrelating, setIsCorrelating] = useState(true);
  const [chains, setChains] = useState<CorrelatedChain[]>([]);
  const [correlationProgress, setCorrelationProgress] = useState({ current: 0, total: 5 });

  // Run correlation engine asynchronously to avoid blocking UI
  useEffect(() => {
    const runCorrelation = async () => {
      setIsCorrelating(true);
      setCorrelationProgress({ current: 0, total: 5 });
      // Yield to browser to show loading state
      await new Promise(resolve => setTimeout(resolve, 100));

      const result = correlateEvents(entries, sigmaMatches, (current, total) => {
        setCorrelationProgress({ current, total });
      });
      setChains(result);
      setIsCorrelating(false);
    };

    runCorrelation();
  }, [entries, sigmaMatches]);

  // Filter and sort chains
  const filteredChains = useMemo(() => {
    let result = chains.filter(c => c.events.length >= minEvents);

    if (severityFilter !== 'all') {
      result = result.filter(c => c.severity === severityFilter);
    }

    // Sort by score (descending)
    result.sort((a, b) => b.score - a.score);

    return result;
  }, [chains, minEvents, severityFilter]);

  const formatDuration = (ms: number): string => {
    if (ms < 1000) return `${ms}ms`;
    if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
    if (ms < 3600000) return `${(ms / 60000).toFixed(1)}m`;
    return `${(ms / 3600000).toFixed(1)}h`;
  };

  // Statistics
  const stats = useMemo(() => {
    const totalEvents = chains.reduce((sum, c) => sum + c.events.length, 0);
    const withMatches = chains.filter(c => c.sigmaMatches.length > 0).length;
    const bySeverity = {
      critical: chains.filter(c => c.severity === 'critical').length,
      high: chains.filter(c => c.severity === 'high').length,
      medium: chains.filter(c => c.severity === 'medium').length,
      low: chains.filter(c => c.severity === 'low').length,
      info: chains.filter(c => c.severity === 'info').length,
    };
    return { total: chains.length, totalEvents, withMatches, bySeverity };
  }, [chains]);

  if (isCorrelating) {
    // Count events with SIGMA matches
    const eventsWithMatches = new Set<LogEntry>();
    for (const matches of sigmaMatches.values()) {
      for (const match of matches) {
        if (match.event) {
          eventsWithMatches.add(match.event);
        }
      }
    }

    return (
      <div className="event-correlation">
        <div className="correlation-header">
          <div className="header-left">
            <button className="back-button" onClick={onBack}>← Back</button>
            <div className="header-title">
              <h1>Event Correlation</h1>
              <p className="tagline">Analyzing event chains...</p>
            </div>
          </div>
        </div>
        <div className="correlation-loading">
          <div className="loading-spinner"></div>
          {eventsWithMatches.size === 0 ? (
            <>
              <p>No SIGMA matches found</p>
              <p className="loading-hint">Event Correlation requires SIGMA detections. Please run SIGMA Detection first.</p>
            </>
          ) : (
            <>
              <p>Correlating {eventsWithMatches.size.toLocaleString()} events with SIGMA matches...</p>
              <div className="correlation-progress">
                <span>{correlationProgress.current} / {correlationProgress.total}</span>
              </div>
              <p className="loading-hint">Building event chains and relationships</p>
            </>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="event-correlation">
      <div className="correlation-header">
        <div className="header-left">
          <button className="back-button" onClick={onBack}>← Back</button>
          <div className="header-title">
            <h1>Event Correlation</h1>
            <p className="tagline">Analyze related event chains and attack patterns</p>
          </div>
        </div>
        <div className="header-actions">
          <div className="view-toggle">
            <button
              className={viewMode === 'story' ? 'active' : ''}
              onClick={() => setViewMode('story')}
              title="Narrative summary of chains"
            >
              Storyline
            </button>
            <button
              className={viewMode === 'chains' ? 'active' : ''}
              onClick={() => setViewMode('chains')}
              title="Detailed chain timeline and tree"
            >
              Chains
            </button>
          </div>
          <button
            className="export-report-btn"
            onClick={() => setShowExportReport(true)}
          >
            Export Report
          </button>
        </div>
      </div>

      {/* SIGMA Note */}
      {sigmaMatches.size === 0 && (
        <div className="sigma-note">
          <span className="note-icon">i</span>
          <span>Run SIGMA Detection first to see matched rules correlated with event chains.</span>
        </div>
      )}

      {/* Statistics Bar */}
      <div className="stats-bar">
        <div className="stat">
          <span className="stat-value">{stats.total}</span>
          <span className="stat-label">Chains</span>
        </div>
        <div className="stat">
          <span className="stat-value">{stats.totalEvents}</span>
          <span className="stat-label">Correlated Events</span>
        </div>
        <div className="stat">
          <span className="stat-value">{stats.withMatches}</span>
          <span className="stat-label">With SIGMA Matches</span>
        </div>
        <div className="stat severity-critical">
          <span className="stat-value">{stats.bySeverity.critical}</span>
          <span className="stat-label">Critical</span>
        </div>
        <div className="stat severity-high">
          <span className="stat-value">{stats.bySeverity.high}</span>
          <span className="stat-label">High</span>
        </div>
        <div className="stat severity-medium">
          <span className="stat-value">{stats.bySeverity.medium}</span>
          <span className="stat-label">Medium</span>
        </div>
      </div>

      {/* Filters */}
      <div className="filters-bar">
        <div className="filter-group">
          <label>Min Events:</label>
          <input
            type="number"
            min={2}
            max={50}
            value={minEvents}
            onChange={(e) => setMinEvents(parseInt(e.target.value) || 3)}
          />
        </div>
        <div className="filter-group">
          <label>Severity:</label>
          <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
            <option value="all">All</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </div>
        <div className="filter-result">
          Showing {filteredChains.length} of {chains.length} chains
        </div>
      </div>

      {/* Main Content */}
      <div className="correlation-content">
        {viewMode === 'story' ? (
          <StorylineSummary chains={filteredChains} formatDuration={formatDuration} />
        ) : (
          <ChainTimeline
            chains={filteredChains}
            formatDuration={formatDuration}
          />
        )}
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

// Timeline visualization component
interface ChainTimelineProps {
  chains: CorrelatedChain[];
  formatDuration: (ms: number) => string;
}

interface StorylineSummaryProps {
  chains: CorrelatedChain[];
  formatDuration: (ms: number) => string;
}

function buildStorySteps(chain: CorrelatedChain) {
  // Get SIGMA-focused events (matched events + context) instead of just first 10
  let eventsToShow: LogEntry[];

  if (chain.sigmaMatches.length === 0) {
    // No SIGMA matches - just show first 10
    eventsToShow = chain.events.slice(0, 10);
  } else {
    // Find all matched event indices
    const matchedIndices = new Set<number>();
    chain.sigmaMatches.forEach(match => {
      const matchEvent = match.event;
      const idx = chain.events.findIndex(e => {
        if (!matchEvent) return false;
        if (e === matchEvent) return true;
        if (e.rawLine && matchEvent.rawLine && e.rawLine === matchEvent.rawLine) return true;
        return false;
      });
      if (idx >= 0) {
        // Add matched event + 2 events before and after for context
        const neighborSpan = 2;
        for (let i = Math.max(0, idx - neighborSpan); i <= Math.min(chain.events.length - 1, idx + neighborSpan); i++) {
          matchedIndices.add(i);
        }
      }
    });

    if (matchedIndices.size === 0) {
      // Fallback if no matches found
      eventsToShow = chain.events.slice(0, 10);
    } else {
      // Sort indices and take up to 10 events
      const sortedIndices = Array.from(matchedIndices).sort((a, b) => a - b).slice(0, 10);
      eventsToShow = sortedIndices.map(i => chain.events[i]);
    }
  }

  return eventsToShow.map(event => {
    const hasMatch = chain.sigmaMatches.some(m => {
      if (m.event === event) return true;
      if (m.event?.rawLine && event.rawLine && m.event.rawLine === event.rawLine) return true;
      return false;
    });

    // Extract fields
    const getField = (name: string) => {
      const match = event.rawLine?.match(new RegExp(`<Data Name="${name}">([^<]*)</Data>`, 'i'));
      return match ? match[1] : null;
    };

    const image = getField('Image');
    const proc = image?.split(/[\\\/]/).pop() || null;
    const commandLine = getField('CommandLine');
    const destIp = getField('DestinationIp');
    const destPort = getField('DestinationPort');
    const targetObject = getField('TargetObject');
    const targetFilename = getField('TargetFilename');
    const imageLoaded = getField('ImageLoaded');
    const parentImage = getField('ParentImage');
    const user = getField('User');

    let summary = '';
    let detail = '';

    // Build narrative based on event type
    switch (event.eventId) {
      case 1: // Process Create
        summary = proc ? `${proc} executed` : 'Process created';
        if (parentImage) {
          const parent = parentImage.split(/[\\\/]/).pop();
          summary += ` by ${parent}`;
        }
        if (commandLine && commandLine !== image) {
          detail = commandLine.length > 80 ? commandLine.substring(0, 80) + '...' : commandLine;
        }
        break;
      case 3: // Network Connection
        summary = proc ? `${proc} connected to network` : 'Network connection';
        if (destIp) {
          detail = destPort ? `${destIp}:${destPort}` : destIp;
        }
        break;
      case 7: // Image Loaded
        if (imageLoaded) {
          const dll = imageLoaded.split(/[\\\/]/).pop();
          summary = proc ? `${proc} loaded ${dll}` : `Loaded ${dll}`;
        } else {
          summary = 'DLL/module loaded';
        }
        break;
      case 10: // Process Access
        summary = proc ? `${proc} accessed another process` : 'Process access';
        break;
      case 11: // File Create
        if (targetFilename) {
          const file = targetFilename.split(/[\\\/]/).pop();
          summary = proc ? `${proc} created ${file}` : `Created ${file}`;
          if (targetFilename.length > 60) {
            detail = '...' + targetFilename.slice(-60);
          }
        } else {
          summary = 'File created';
        }
        break;
      case 12: case 13: case 14: // Registry events
        if (targetObject) {
          const keyParts = targetObject.split('\\');
          const keyName = keyParts[keyParts.length - 1];
          summary = proc ? `${proc} modified registry` : 'Registry modified';
          detail = keyName.length > 40 ? '...' + keyName.slice(-40) : keyName;
        } else {
          summary = 'Registry activity';
        }
        break;
      case 22: // DNS Query
        summary = proc ? `${proc} performed DNS query` : 'DNS query';
        const queryName = getField('QueryName');
        if (queryName) {
          detail = queryName;
        }
        break;
      case 23: // File Delete
        if (targetFilename) {
          const file = targetFilename.split(/[\\\/]/).pop();
          summary = proc ? `${proc} deleted ${file}` : `Deleted ${file}`;
        } else {
          summary = 'File deleted';
        }
        break;
      default:
        summary = proc ? `${proc} (Event ${event.eventId})` : `Event ${event.eventId}`;
    }

    // Add user context if available
    if (user && user !== 'N/A' && !user.includes('SYSTEM')) {
      summary += ` [${user.split('\\').pop()}]`;
    }

    return {
      time: event.timestamp,
      summary,
      detail,
      hasMatch,
      matchedRules: hasMatch ? chain.sigmaMatches.filter(m =>
        (m.event === event) ||
        (m.event?.rawLine && event.rawLine && m.event.rawLine === event.rawLine)
      ).map(m => m.rule.title) : []
    };
  });
}

function StorylineSummary({ chains }: StorylineSummaryProps) {
  const formatRange = (chain: CorrelatedChain) => {
    const opts: Intl.DateTimeFormatOptions = { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false };
    if (!chain.startTime || !chain.endTime) return 'Unknown time range';
    try {
      return `${chain.startTime.toLocaleTimeString(undefined, opts)} → ${chain.endTime.toLocaleTimeString(undefined, opts)}`;
    } catch {
      return 'Invalid time range';
    }
  };

  const getTopRule = (chain: CorrelatedChain) => {
    const match = chain.sigmaMatches[0];
    return match?.rule?.title || match?.rule?.id || null;
  };

  return (
    <div className="story-cards">
      {chains.map(chain => {
        const steps = buildStorySteps(chain);
        const topRule = getTopRule(chain);
        const actors = Array.from(chain.involvedProcesses).slice(0, 3);
        const hosts = Array.from(chain.involvedHosts).slice(0, 2);

        return (
          <div key={chain.id} className="story-card">
            <div className="story-card-header">
              <div className="left">
                <span className={`severity-badge severity-${chain.severity}`}>{chain.severity.toUpperCase()}</span>
                <h3>{chain.summary}</h3>
              </div>
              <div className="right">
                <span className="range">{formatRange(chain)}</span>
                <span className="count">{chain.events.length} events</span>
                {chain.sigmaMatches.length > 0 && (
                  <span className="sigma-chip">{chain.sigmaMatches.length} detections</span>
                )}
              </div>
            </div>

            <div className="story-meta">
              <div className="meta-row">
                <span className="meta-label">Key actors</span>
                <span className="meta-value">{actors.length ? actors.join(', ') : 'Unknown'}</span>
              </div>
              <div className="meta-row">
                <span className="meta-label">Hosts</span>
                <span className="meta-value">{hosts.length ? hosts.join(', ') : 'Unknown'}</span>
              </div>
              <div className="meta-row">
                <span className="meta-label">Top detection</span>
                <span className="meta-value">{topRule || 'None'}</span>
              </div>
            </div>

            <div className="story-steps">
              {steps.map((step, idx) => (
                <div key={idx} className={`story-step ${step.hasMatch ? 'has-detection' : ''}`}>
                  <div className="step-marker">
                    <span className={`marker-dot ${step.hasMatch ? 'detected' : ''}`} />
                    <span className="step-time">
                      {step.time ? (
                        (() => {
                          try {
                            return step.time.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
                          } catch {
                            return 'Invalid time';
                          }
                        })()
                      ) : 'Unknown'}
                    </span>
                  </div>
                  <div className="step-body">
                    <p className="step-summary">{step.summary}</p>
                    {step.detail && <p className="step-detail">{step.detail}</p>}
                    {step.hasMatch && step.matchedRules.length > 0 && (
                      <div className="step-detections">
                        {step.matchedRules.map((rule, rIdx) => (
                          <span key={rIdx} className="detection-badge">{rule}</span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              ))}
              {chain.events.length > steps.length && (
                <div className="story-more">+ {chain.events.length - steps.length} more events</div>
              )}
            </div>
          </div>
        );
      })}

      {chains.length === 0 && (
        <div className="story-empty">No chains match the current filters.</div>
      )}
    </div>
  );
}

function ChainTimeline({ chains, formatDuration }: ChainTimelineProps) {
  const [expandedChains, setExpandedChains] = useState<Set<string>>(new Set());
  const [showFullChains, setShowFullChains] = useState<Set<string>>(new Set());

  const matchesEvent = (match: SigmaRuleMatch, event: LogEntry): boolean => {
    const matchEvent = match.event;
    if (!matchEvent) return false;

    // Exact object reference match (most reliable)
    if (matchEvent === event) return true;

    // Exact rawLine match (second most reliable)
    if (matchEvent.rawLine && event.rawLine && matchEvent.rawLine === event.rawLine) return true;

    // No other matching - timestamp+eventId matching is too unreliable
    // because different events can have the same eventId (e.g., multiple process creates)
    return false;
  };

  // Derive a SIGMA-focused subset: only matched events plus +/- neighborSpan context
  const getSigmaFocusedEvents = (chain: CorrelatedChain, neighborSpan: number = 2): { events: LogEntry[]; overflow: number } => {
    // If no matches, fall back to the first 10 to avoid noise
    if (chain.sigmaMatches.length === 0) {
      const fallback = chain.events.slice(0, 10);
      return { events: fallback, overflow: chain.events.length - fallback.length };
    }

    const indices = new Set<number>();
    chain.sigmaMatches.forEach(match => {
      const matchEvent = match.event;
      const idx = chain.events.findIndex(e => {
        if (!matchEvent) return false;

        // Exact object reference match
        if (e === matchEvent) return true;

        // Exact rawLine match
        if (e.rawLine && matchEvent.rawLine && e.rawLine === matchEvent.rawLine) return true;

        // No other matching - keep it strict
        return false;
      });
      if (idx >= 0) {
        for (let i = Math.max(0, idx - neighborSpan); i <= Math.min(chain.events.length - 1, idx + neighborSpan); i++) {
          indices.add(i);
        }
      }
    });

    // If somehow no indices were found, fall back to the first 10
    if (indices.size === 0) {
      const fallback = chain.events.slice(0, 10);
      return { events: fallback, overflow: chain.events.length - fallback.length };
    }

    const sorted = Array.from(indices).sort((a, b) => a - b);
    const events = sorted.map(i => chain.events[i]);
    return { events, overflow: chain.events.length - events.length };
  };

  const toggleExpand = (chainId: string) => {
    setExpandedChains(prev => {
      const next = new Set(prev);
      if (next.has(chainId)) {
        next.delete(chainId);
      } else {
        next.add(chainId);
      }
      return next;
    });
  };

  const getProcessName = (event: LogEntry): string | null => {
    const image =
      (event.eventData && event.eventData.Image) ||
      (() => {
        if (!event.rawLine) return null;
        const match = event.rawLine.match(/<Data Name="Image">([^<]+)<\/Data>/i);
        return match ? match[1] : null;
      })();

    if (!image) return null;
    const parts = image.split(/[\\\/]/);
    return parts[parts.length - 1];
  };

  const formatTime = (date: Date | null | undefined) => {
    if (!date) return 'Unknown';
    try {
      return date.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
    } catch {
      return 'Invalid time';
    }
  };

  return (
    <div className="chain-timeline-container">
      {chains.length === 0 ? (
        <div className="no-chains">No event chains found matching the current filters.</div>
      ) : (
        <div className="timeline-list">
          {chains.map(chain => {
            const isExpanded = expandedChains.has(chain.id);
            const useFull = showFullChains.has(chain.id);
            const sigmaFocus = useFull ? { events: chain.events, overflow: 0 } : getSigmaFocusedEvents(chain);
            const displayEvents = sigmaFocus.events;
            const overflowCount = sigmaFocus.overflow;

            return (
              <div
                key={chain.id}
                className={`timeline-chain ${isExpanded ? 'expanded' : ''}`}
              >
                {/* Chain Header */}
                <div className="timeline-chain-header" onClick={() => toggleExpand(chain.id)}>
                  <div className="chain-info">
                    <span className={`severity-badge severity-${chain.severity}`}>
                      {chain.severity.toUpperCase()}
                    </span>
                    <span className="chain-events-count">{chain.events.length} events</span>
                    <span className="chain-duration">{formatDuration(chain.duration)}</span>
                    {chain.sigmaMatches.length > 0 && (
                      <span className="chain-sigma-count">{chain.sigmaMatches.length} SIGMA</span>
                    )}
                  </div>
                  <div className="chain-summary">{chain.summary}</div>
                  <span className="expand-indicator">
                    {isExpanded ? '−' : '+'}
                  </span>
                </div>

                {/* Timeline markers */}
                <div className="timeline-bar-container">
                  <div className="timeline-times">
                    <span>{formatTime(chain.startTime)}</span>
                    <span>{formatTime(chain.endTime)}</span>
                  </div>
                </div>

                {/* Expanded Events - Process Tree */}
                {isExpanded && (
                  <div className="timeline-events-expanded">
                    <div className="view-mode-toggle">
                      <button onClick={() => {
                        setShowFullChains(prev => {
                          const next = new Set(prev);
                          if (next.has(chain.id)) {
                            next.delete(chain.id);
                          } else {
                            next.add(chain.id);
                          }
                          return next;
                        });
                      }}>
                        {useFull ? 'Show SIGMA context only' : 'Show full chain'}
                      </button>
                      {!useFull && overflowCount > 0 && (
                        <span className="overflow-note">
                          Showing {displayEvents.length} of {chain.events.length} (SIGMA matches ± neighbors). {overflowCount} hidden.
                        </span>
                      )}
                    </div>
                    <ProcessTree
                      chain={chain}
                      displayEvents={displayEvents}
                      overflowCount={overflowCount}
                      getProcessName={getProcessName}
                      formatTime={formatTime}
                      matchesEvent={matchesEvent}
                    />
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// Process Tree Component
interface ProcessTreeProps {
  chain: CorrelatedChain;
  displayEvents: LogEntry[]; // capped list
  overflowCount: number;
  getProcessName: (event: LogEntry) => string | null;
  formatTime: (date: Date | null | undefined) => string;
  matchesEvent: (match: SigmaRuleMatch, event: LogEntry) => boolean;
}

interface ProcessNode {
  process: string;
  events: LogEntry[];
  hasMatch: boolean;
  children: ProcessNode[];
  depth: number;
}

function ProcessTree({ chain, displayEvents, overflowCount, getProcessName, formatTime, matchesEvent }: ProcessTreeProps) {
  const getField = (event: LogEntry, fieldName: string): string | null => {
    if (event.eventData && event.eventData[fieldName]) {
      return event.eventData[fieldName];
    }
    if (!event.rawLine) return null;
    const match = event.rawLine.match(new RegExp(`<Data Name="${fieldName}">([^<]*)</Data>`, 'i'));
    return match ? match[1] : null;
  };

  // Build hierarchical process tree using ProcessGuid for accurate parent-child relationships
  const processTree = useMemo(() => {
    // First, collect all process instances with their GUIDs
    const processInstances = new Map<string, {
      processGuid: string;
      processName: string;
      parentProcessGuid: string | null;
      events: LogEntry[];
      hasMatch: boolean;
      firstTimestamp: number;
    }>();

    // Also track by process name for fallback grouping (non-process events)
    const nonGuidEvents = new Map<string, {
      processName: string;
      events: LogEntry[];
      hasMatch: boolean;
      firstTimestamp: number;
    }>();

    displayEvents.forEach(event => {
      const processGuid = getField(event, 'ProcessGuid');
      const parentProcessGuid = getField(event, 'ParentProcessGuid');
      const processName = getProcessName(event) || `Event ${event.eventId}`;
      const hasMatch = chain.sigmaMatches.some(m => {
        if (m.event === event) return true;
        if (m.event?.rawLine && event.rawLine && m.event.rawLine === event.rawLine) return true;
        // Safely handle timestamps with validation
        if (m.timestamp && event.timestamp) {
          try {
            const matchTime = m.timestamp instanceof Date ? m.timestamp.getTime() : new Date(m.timestamp).getTime();
            const eventTime = event.timestamp instanceof Date ? event.timestamp.getTime() : new Date(event.timestamp).getTime();
            return matchTime === eventTime;
          } catch {
            return false;
          }
        }
        return false;
      });

      if (processGuid) {
        // Use ProcessGuid as unique identifier
        const existing = processInstances.get(processGuid);
        if (existing) {
          existing.events.push(event);
          if (hasMatch) existing.hasMatch = true;
        } else {
          processInstances.set(processGuid, {
            processGuid,
            processName,
            parentProcessGuid,
            events: [event],
            hasMatch,
            firstTimestamp: event.timestamp ? (event.timestamp instanceof Date ? event.timestamp.getTime() : new Date(event.timestamp).getTime()) : 0
          });
        }
      } else {
        // Fallback: group by process name for events without ProcessGuid
        const existing = nonGuidEvents.get(processName);
        if (existing) {
          existing.events.push(event);
          if (hasMatch) existing.hasMatch = true;
        } else {
          nonGuidEvents.set(processName, {
            processName,
            events: [event],
            hasMatch,
            firstTimestamp: event.timestamp ? (event.timestamp instanceof Date ? event.timestamp.getTime() : new Date(event.timestamp).getTime()) : 0
          });
        }
      }
    });

    // Build tree structure
    const buildTree = (): ProcessNode[] => {
      const nodes = new Map<string, ProcessNode>();
      const rootNodes: ProcessNode[] = [];

      // Create nodes for all process instances (by GUID)
      processInstances.forEach((data, guid) => {
        nodes.set(guid, {
          process: data.processName,
          events: data.events,
          hasMatch: data.hasMatch,
          children: [],
          depth: 0
        });
      });

      // Create nodes for non-GUID events (use process name as key with prefix)
      nonGuidEvents.forEach((data, name) => {
        const key = `_name_${name}`;
        nodes.set(key, {
          process: data.processName,
          events: data.events,
          hasMatch: data.hasMatch,
          children: [],
          depth: 0
        });
      });

      // Establish parent-child relationships using ParentProcessGuid
      processInstances.forEach((data, guid) => {
        const node = nodes.get(guid);
        if (!node) return; // Skip if node not found

        const parentGuid = data.parentProcessGuid;

        if (parentGuid && nodes.has(parentGuid)) {
          const parentNode = nodes.get(parentGuid);
          if (parentNode) {
            parentNode.children.push(node);
          } else {
            rootNodes.push(node);
          }
        } else {
          rootNodes.push(node);
        }
      });

      // Add non-GUID events as root nodes
      nonGuidEvents.forEach((_, name) => {
        const key = `_name_${name}`;
        const node = nodes.get(key);
        if (node) {
          rootNodes.push(node);
        }
      });

      // Calculate depths and sort children by timestamp
      const setDepths = (node: ProcessNode, depth: number, maxDepth: number = 100) => {
        // Prevent infinite recursion
        if (depth > maxDepth) {
          console.warn(`Maximum process tree depth (${maxDepth}) exceeded`);
          return;
        }
        node.depth = depth;
        // Sort children by timestamp, with null safety
        node.children.sort((a, b) => {
          const aTime = a.events[0]?.timestamp;
          const bTime = b.events[0]?.timestamp;
          if (!aTime || !bTime) return 0;
          try {
            const aMs = aTime instanceof Date ? aTime.getTime() : new Date(aTime).getTime();
            const bMs = bTime instanceof Date ? bTime.getTime() : new Date(bTime).getTime();
            return aMs - bMs;
          } catch {
            return 0;
          }
        });
        node.children.forEach(child => setDepths(child, depth + 1, maxDepth));
      };

      // Sort root nodes by timestamp with null safety
      rootNodes.sort((a, b) => {
        const aTime = a.events[0]?.timestamp;
        const bTime = b.events[0]?.timestamp;
        if (!aTime || !bTime) return 0;
        try {
          const aMs = aTime instanceof Date ? aTime.getTime() : new Date(aTime).getTime();
          const bMs = bTime instanceof Date ? bTime.getTime() : new Date(bTime).getTime();
          return aMs - bMs;
        } catch {
          return 0;
        }
      });
      rootNodes.forEach(root => setDepths(root, 0));

      return rootNodes;
    };

    return buildTree();
  }, [chain, getProcessName]);

  // Flatten tree for rendering with depth info
  const flattenTree = (nodes: ProcessNode[]): ProcessNode[] => {
    const result: ProcessNode[] = [];
    const traverse = (node: ProcessNode) => {
      result.push(node);
      node.children.forEach(traverse);
    };
    nodes.forEach(traverse);
    return result;
  };

  const flatNodes = flattenTree(processTree);

  return (
    <div className="process-tree">
      {flatNodes.map((node, nodeIdx) => (
        <div key={nodeIdx} className={`process-group ${node.hasMatch ? 'has-match' : ''}`} style={{ marginLeft: `${node.depth * 20}px` }}>
          <div className="process-content">
            <div className="process-header">
              <span className="process-icon">
                {node.hasMatch ? '!' : '>'}
              </span>
              <span className="process-name">{node.process}</span>
              <span className="process-event-count">{node.events.length} event{node.events.length > 1 ? 's' : ''}</span>
            </div>
            <div className="process-events">
              {node.events.slice(0, 10).map((event, eventIdx) => {
                const commandLine = getField(event, 'CommandLine');
                const user = getField(event, 'User');

                // Find all matching SIGMA rules for this event
                const matchingRules = chain.sigmaMatches.filter(m => matchesEvent(m, event));
                // Deduplicate by rule ID to avoid showing the same rule multiple times
                const uniqueMatchingRules = Array.from(
                  new Map(matchingRules.map(m => [m.rule.id, m])).values()
                );
                const hasMatch = uniqueMatchingRules.length > 0;
                const isLastRendered = eventIdx === Math.min(node.events.length, 10) - 1;

                // Event-specific fields
                const targetObject = getField(event, 'TargetObject');
                const details = getField(event, 'Details');
                const destIp = getField(event, 'DestinationIp');
                const destPort = getField(event, 'DestinationPort');
                const destHostname = getField(event, 'DestinationHostname');
                const sourceIp = getField(event, 'SourceIp');
                const sourcePort = getField(event, 'SourcePort');
                const targetFilename = getField(event, 'TargetFilename');
                const imageLoaded = getField(event, 'ImageLoaded');

                return (
                  <div key={eventIdx} className={`process-event ${hasMatch ? 'has-match' : ''}`}>
                    <div className="event-header">
                      <div className="event-meta">
                        <span className="event-id">ID: {event.eventId}</span>
                        <span className="event-time">{formatTime(event.timestamp)}</span>
                      </div>
                      {hasMatch && (
                        <span className="sigma-badge-wrapper">
                          <span className="sigma-badge">SIGMA</span>
                          <span className="sigma-tooltip">
                            {uniqueMatchingRules.map((m, idx) => (
                              <span key={idx} className="rule-line">{m.rule.title}</span>
                            ))}
                          </span>
                        </span>
                      )}
                    </div>
                    {commandLine && (
                      <div className="event-detail" title={commandLine}>
                        <span className="detail-label">CMD:</span> {commandLine.length > 70 ? commandLine.substring(0, 70) + '...' : commandLine}
                      </div>
                    )}
                    {targetObject && (
                      <div className="event-detail" title={targetObject}>
                        <span className="detail-label">Registry:</span> {targetObject.length > 100 ? '...' + targetObject.slice(-100) : targetObject}
                      </div>
                    )}
                    {details && (
                      <div className="event-detail" title={details}>
                        <span className="detail-label">Value:</span> {details.length > 50 ? details.substring(0, 50) + '...' : details}
                      </div>
                    )}
                    {destIp && (
                      <div className="event-detail">
                        <span className="detail-label">Dest:</span> {destIp}{destPort ? `:${destPort}` : ''}{destHostname ? ` (${destHostname})` : ''}
                      </div>
                    )}
                    {sourceIp && !destIp && (
                      <div className="event-detail">
                        <span className="detail-label">Source:</span> {sourceIp}{sourcePort ? `:${sourcePort}` : ''}
                      </div>
                    )}
                    {targetFilename && (
                      <div className="event-detail" title={targetFilename}>
                        <span className="detail-label">File:</span> {targetFilename.length > 60 ? '...' + targetFilename.slice(-60) : targetFilename}
                      </div>
                    )}
                    {imageLoaded && !commandLine && (
                      <div className="event-detail" title={imageLoaded}>
                        <span className="detail-label">Loaded:</span> {imageLoaded.length > 60 ? '...' + imageLoaded.slice(-60) : imageLoaded}
                      </div>
                    )}
                    {user && <div className="event-detail"><span className="detail-label">User:</span> {user}</div>}
                    {isLastRendered && node.events.length > 10 && (
                      <div className="event-detail overflow-note">
                        + {node.events.length - 10} more event{node.events.length - 10 > 1 ? 's' : ''} not shown in this chain
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      ))}
      {overflowCount > 0 && (
        <div className="process-event overflow-note">
          + {overflowCount} more event{overflowCount > 1 ? 's' : ''} not shown in this chain
        </div>
      )}
    </div>
  );
}
