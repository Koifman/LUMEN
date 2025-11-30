import { useMemo, useState, useEffect, useRef, useCallback } from 'react';
import { LogEntry } from '../types';
import { getSeverityColor, getSeverityIcon } from '../lib/sigmaRules';
import { SigmaEngine } from '../lib/sigma';
import { SigmaRuleMatch } from '../lib/sigma/types';
import {
  processEventsOptimized,
  OptimizedMatchStats
} from '../lib/sigma/engine/optimizedMatcher';
import './SigmaDetections.css';

// ============================================================================
// VIRTUAL SCROLLING CONSTANTS
// ============================================================================
const INITIAL_VISIBLE_COUNT = 10;  // Number of cards to show initially
const LOAD_MORE_COUNT = 10;        // Number of cards to add when scrolling

/**
 * Format selection definition for tooltip display
 */
function formatSelectionForTooltip(selection: any, selectionName: string): string {
  if (!selection) return `${selectionName}: (no definition available)`;

  try {
    // Convert to YAML-like format
    let yaml = `${selectionName}:\n`;

    if (Array.isArray(selection)) {
      // Array-based selection (OR logic)
      selection.forEach(item => {
        yaml += '  -';
        const entries = Object.entries(item);
        if (entries.length === 1) {
          const [key, value] = entries[0];
          yaml += ` ${key}: ${formatValue(value)}\n`;
        } else {
          yaml += '\n';
          entries.forEach(([key, value]) => {
            yaml += `    ${key}: ${formatValue(value)}\n`;
          });
        }
      });
    } else {
      // Object-based selection (AND logic)
      Object.entries(selection).forEach(([key, value]) => {
        yaml += `  ${key}: ${formatValue(value)}\n`;
      });
    }

    return yaml.trim();
  } catch (e) {
    return `${selectionName}: ${JSON.stringify(selection)}`;
  }
}

function formatValue(value: any): string {
  if (Array.isArray(value)) {
    if (value.length === 1) return `'${value[0]}'`;
    return '\n' + value.map(v => `      - '${v}'`).join('\n');
  }
  return `'${value}'`;
}

interface SigmaDetectionsProps {
  events: LogEntry[];
  sigmaEngine?: SigmaEngine;
  onMatchesUpdate?: (matches: Map<string, SigmaRuleMatch[]>) => void;
  cachedMatches?: Map<string, SigmaRuleMatch[]>;
}

export default function SigmaDetections({ events, sigmaEngine, onMatchesUpdate, cachedMatches }: SigmaDetectionsProps) {
  const [expandedRule, setExpandedRule] = useState<string | null>(null);
  const [matches, setMatches] = useState<Map<string, SigmaRuleMatch[]>>(cachedMatches || new Map());
  const [isLoading, setIsLoading] = useState(!(cachedMatches && cachedMatches.size > 0));
  const [progress, setProgress] = useState({ processed: 0, total: 0, matchesFound: 0 });
  const [optimizationStats, setOptimizationStats] = useState<OptimizedMatchStats | null>(null);

  // Virtual scrolling state
  const [visibleCount, setVisibleCount] = useState(INITIAL_VISIBLE_COUNT);
  const containerRef = useRef<HTMLDivElement>(null);

  // Use ref for callback to avoid re-triggering effect
  const onMatchesUpdateRef = useRef(onMatchesUpdate);
  onMatchesUpdateRef.current = onMatchesUpdate;

  // Sentinel ref for intersection observer (placed at bottom of list)
  const sentinelRef = useRef<HTMLDivElement>(null);

  // Reset visible count when matches change
  useEffect(() => {
    setVisibleCount(INITIAL_VISIBLE_COUNT);
  }, [matches]);

  // Legacy scroll handler (backup for browsers without IntersectionObserver)
  const handleScroll = useCallback(() => {
    if (!containerRef.current) return;

    const { scrollTop, scrollHeight, clientHeight } = containerRef.current;
    const scrollThreshold = 200;

    if (scrollHeight - scrollTop - clientHeight < scrollThreshold) {
      setVisibleCount(prev => prev + LOAD_MORE_COUNT);
    }
  }, []);

  // Run SIGMA matching asynchronously with optimized processing
  useEffect(() => {
    // Skip processing if we already have cached matches (initial load only)
    if (cachedMatches && cachedMatches.size > 0 && matches.size === 0) {
      setMatches(cachedMatches);
      setIsLoading(false);
      // Notify parent with cached results
      if (onMatchesUpdateRef.current) {
        onMatchesUpdateRef.current(cachedMatches);
      }
      return;
    }

    // Skip if we already have matches (processing completed)
    if (matches.size > 0) {
      return;
    }

    if (!sigmaEngine || events.length === 0) {
      setMatches(new Map());
      setIsLoading(false);
      setOptimizationStats(null);
      return;
    }

    setIsLoading(true);
    setProgress({ processed: 0, total: events.length, matchesFound: 0 });

    const rules = sigmaEngine.getAllRules();

    // Start optimized processing on main thread with yields
    processEventsOptimized(
      events,
      rules,
      (processed, total, stats) => {
        setProgress({ processed, total, matchesFound: stats?.matchesFound || 0 });
      },
      1000 // Larger chunk size for better throughput
    ).then(({ matches: result, stats }) => {
      setMatches(result);
      setOptimizationStats(stats);
      setIsLoading(false);
      // Notify parent that analysis is complete
      if (onMatchesUpdateRef.current) {
        onMatchesUpdateRef.current(result);
      }
    });

    // No cleanup needed - we want analysis to complete
  }, [events, sigmaEngine]);

  // Calculate statistics from matches
  const stats = useMemo(() => {
    const totalMatches = Array.from(matches.values()).reduce((sum, m) => sum + m.length, 0);
    const bySeverity = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    };

    for (const ruleMatches of matches.values()) {
      if (ruleMatches.length > 0) {
        const severity = ruleMatches[0].rule.level || 'medium';
        bySeverity[severity as keyof typeof bySeverity] += ruleMatches.length;
      }
    }

    return {
      totalRules: matches.size,
      matchedRules: matches.size,
      totalMatches,
      bySeverity
    };
  }, [matches]);

  // Sort rules by severity (critical first)
  const sortedMatches = useMemo(() => {
    const entries = Array.from(matches.entries());
    return entries.sort((a, b) => {
      const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, informational: 4, info: 4 };
      const severityA = a[1][0]?.rule.level || 'medium';
      const severityB = b[1][0]?.rule.level || 'medium';
      return (severityOrder[severityA] || 2) - (severityOrder[severityB] || 2);
    });
  }, [matches]);

  // Window scroll handler for infinite scroll
  // Using window scroll since parent containers control scrolling
  // Track last scroll position to only trigger on actual scroll down
  const lastScrollY = useRef(0);
  const hasScrolledOnce = useRef(false);

  useEffect(() => {
    if (sortedMatches.length === 0) return;

    // Reset scroll tracking when matches change
    lastScrollY.current = window.scrollY;
    hasScrolledOnce.current = false;

    const handleWindowScroll = () => {
      const currentScrollY = window.scrollY;

      // Only process if user has scrolled down from last position
      if (currentScrollY <= lastScrollY.current && hasScrolledOnce.current) {
        lastScrollY.current = currentScrollY;
        return;
      }

      hasScrolledOnce.current = true;
      lastScrollY.current = currentScrollY;

      const sentinel = sentinelRef.current;
      if (!sentinel) return;

      // Check if sentinel is near the viewport bottom
      const rect = sentinel.getBoundingClientRect();
      const windowHeight = window.innerHeight;

      // Load more when sentinel is within 150px of viewport bottom
      if (rect.top < windowHeight + 150) {
        setVisibleCount(prev => {
          if (prev >= sortedMatches.length) return prev;
          return Math.min(prev + LOAD_MORE_COUNT, sortedMatches.length);
        });
      }
    };

    // Throttle scroll events
    let ticking = false;
    const throttledScroll = () => {
      if (!ticking) {
        window.requestAnimationFrame(() => {
          handleWindowScroll();
          ticking = false;
        });
        ticking = true;
      }
    };

    window.addEventListener('scroll', throttledScroll, { passive: true });

    return () => {
      window.removeEventListener('scroll', throttledScroll);
    };
  }, [sortedMatches.length]);

  const toggleExpand = (ruleId: string) => {
    setExpandedRule(expandedRule === ruleId ? null : ruleId);
  };

  // Get total rule count from engine
  const totalRules = sigmaEngine?.getAllRules().length || 0;

  return (
    <div className="sigma-detections">
      <div className="sigma-header">
        <h2>SIGMA Threat Detections</h2>
        {totalRules > 0 && (
          <p className="sigma-subtitle">
            Automated detection using {totalRules} security rules
          </p>
        )}
      </div>

      {/* Statistics Summary */}
      <div className="sigma-summary">
        {isLoading ? (
          <div className="loading-state">
            <div className="sigma-loading-spinner"></div>
            <h3>Analyzing Events</h3>
            <p>
              Scanning {events.length.toLocaleString()} events against SIGMA rules...
            </p>
            <div className="progress-bar">
              <div
                className="progress-fill"
                style={{ width: `${(progress.processed / Math.max(progress.total, 1)) * 100}%` }}
              />
            </div>
            <div className="progress-text">
              {Math.round((progress.processed / Math.max(progress.total, 1)) * 100)}%
              {progress.matchesFound > 0 && ` • ${progress.matchesFound} detections found`}
            </div>
          </div>
        ) : stats.totalMatches === 0 ? (
          <div className="no-threats">
            <span className="success-icon">OK</span>
            <h3>No Threats Detected</h3>
            <p>All {events.length} events passed security checks</p>
          </div>
        ) : (
          <div className="threat-stats">
            <div className="stat-item">
              <span className="stat-number">{stats.totalMatches}</span>
              <span className="stat-label">Total Detections</span>
            </div>
            {stats.bySeverity.critical > 0 && (
              <div className="stat-item critical">
                <span className="stat-icon">🔴</span>
                <span className="stat-number">{stats.bySeverity.critical}</span>
                <span className="stat-label">Critical</span>
              </div>
            )}
            {stats.bySeverity.high > 0 && (
              <div className="stat-item high">
                <span className="stat-icon">🟠</span>
                <span className="stat-number">{stats.bySeverity.high}</span>
                <span className="stat-label">High</span>
              </div>
            )}
            {stats.bySeverity.medium > 0 && (
              <div className="stat-item medium">
                <span className="stat-icon">🟡</span>
                <span className="stat-number">{stats.bySeverity.medium}</span>
                <span className="stat-label">Medium</span>
              </div>
            )}
            {stats.bySeverity.low > 0 && (
              <div className="stat-item low">
                <span className="stat-icon">🟢</span>
                <span className="stat-number">{stats.bySeverity.low}</span>
                <span className="stat-label">Low</span>
              </div>
            )}
          </div>
        )}
        {!isLoading && optimizationStats && (
          <p className="optimization-info">
            Analyzed in {(optimizationStats.processingTimeMs / 1000).toFixed(1)}s
          </p>
        )}
      </div>

      {/* Detection Cards - Virtual Scrolling */}
      {!isLoading && sortedMatches.length > 0 && (
        <div
          className="sigma-matches"
          ref={containerRef}
          onScroll={handleScroll}
        >
          {sortedMatches.slice(0, visibleCount).map(([ruleId, ruleMatches]) => {
            if (ruleMatches.length === 0) return null;

            const rule = ruleMatches[0].rule;
            const isExpanded = expandedRule === ruleId;

            const level = rule.level || 'medium';

            return (
              <div
                key={ruleId}
                className={`sigma-match ${level}`}
                style={{ borderLeftColor: getSeverityColor(level) }}
              >
                <div className="match-header" onClick={() => toggleExpand(ruleId)}>
                  <div className="match-title">
                    <span className="severity-icon">{getSeverityIcon(level)}</span>
                    <h3>{rule.title}</h3>
                  </div>
                  <div className="match-meta">
                    <span className="match-count">
                      {ruleMatches.length} {ruleMatches.length === 1 ? 'event' : 'events'}
                    </span>
                    <button className="expand-btn">
                      {isExpanded ? '▼' : '▶'}
                    </button>
                  </div>
                </div>

                <p className="match-description">{rule.description}</p>
                {rule.author && (
                  <div className="rule-author">
                    <span className="author-label">Rule Author:</span> {rule.author}
                  </div>
                )}

                <div className="match-info">
                  <span className="severity-badge" style={{ backgroundColor: getSeverityColor(level) }}>
                    {level.toUpperCase()}
                  </span>
                  {rule.tags && rule.tags.length > 0 && (
                    <span className="tags">
                      {rule.tags.slice(0, 2).map(tag => (
                        <span key={tag} className="tag">{tag}</span>
                      ))}
                    </span>
                  )}
                </div>

                {/* Expandable Details */}
                {isExpanded && (
                  <div className="match-details">
                    <h4>Matched Events ({ruleMatches.length})</h4>
                    <div className="matched-events">
                      {ruleMatches.slice(0, 10).map((match, idx) => {
                        // Extract matched fields with more details from selection matches
                        const allFieldMatches: Array<{
                          field: string;
                          value: any;
                          selection: string;
                          selectionDef?: any;
                          modifier?: string;
                        }> = [];

                        if (match.selectionMatches && match.selectionMatches.length > 0) {
                          for (const selMatch of match.selectionMatches) {
                            // Get the selection definition from compiled rule
                            let selectionDef;
                            if (match.compiledRule && match.compiledRule.selections) {
                              const selection = match.compiledRule.selections.get(selMatch.selection);
                              selectionDef = selection?.originalDefinition;
                            }

                            if (selMatch.fieldMatches) {
                              for (const fm of selMatch.fieldMatches) {
                                // For filter selections (NOT conditions), show all fields even if undefined
                                // For regular selections, skip undefined/null fields (Sysmon-only fields)
                                const isFilterSelection = selMatch.selection.toLowerCase().startsWith('filter');

                                if (!isFilterSelection && (fm.value === undefined || fm.value === null)) {
                                  continue;
                                }

                                // Include ALL field matches, not just matched ones
                                // This is important for NOT conditions where fields are expected to NOT match
                                allFieldMatches.push({
                                  field: fm.field,
                                  value: fm.value,
                                  selection: selMatch.selection,
                                  selectionDef: selectionDef,
                                  modifier: fm.modifier
                                });
                              }
                            }
                          }
                        }

                        const eventData = match.event as any;
                        const timestamp = eventData.timestamp || match.timestamp || new Date();

                        return (
                          <div key={idx} className="matched-event">
                            <div className="event-time">
                              {timestamp instanceof Date ? timestamp.toLocaleString() : new Date(timestamp).toLocaleString()}
                            </div>
                            <div className="event-info">
                              <span>Computer: {eventData.Computer || eventData.computer || 'N/A'}</span>
                              <span>Event ID: {eventData.EventID || eventData.eventId || 'N/A'}</span>
                              <span>Source: {eventData.Provider || eventData.source || 'N/A'}</span>
                            </div>
                            {allFieldMatches.length > 0 && (
                              <div className="matched-fields">
                                <div className="matched-fields-header">Matched Fields:</div>
                                {allFieldMatches.map((fm, fmIdx) => (
                                  <div key={fmIdx} className="field-match">
                                    <div className="field-match-header">
                                      <span className="field-name">{fm.field}</span>
                                      {fm.modifier && fm.modifier !== 'equals' && (
                                        <span className="field-modifier">{fm.modifier}</span>
                                      )}
                                      {fm.selection.toLowerCase().startsWith('filter') && (
                                        <span className="field-not-label">NOT</span>
                                      )}
                                      <span className="field-selection-wrapper">
                                        <span className="field-selection">
                                          {fm.selection}
                                        </span>
                                        {fm.selectionDef && (
                                          <span className="field-selection-tooltip">
                                            <pre>{formatSelectionForTooltip(fm.selectionDef, fm.selection)}</pre>
                                          </span>
                                        )}
                                      </span>
                                    </div>
                                    <div className="field-value">
                                      {fm.value === undefined || fm.value === null
                                        ? <span style={{ fontStyle: 'italic', color: 'var(--text-dim)' }}>
                                            {fm.value === null ? '(null)' : '(not found in event)'}
                                          </span>
                                        : (fm.value === ''
                                          ? <span style={{ fontStyle: 'italic', color: 'var(--text-dim)' }}>(empty)</span>
                                          : <>
                                              {String(fm.value).substring(0, 200)}
                                              {String(fm.value).length > 200 ? '...' : ''}
                                            </>
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
                      {ruleMatches.length > 10 && (
                        <div className="more-events">
                          +{ruleMatches.length - 10} more events
                        </div>
                      )}
                    </div>

                    {rule.references && rule.references.length > 0 && (
                      <div className="references">
                        <h5>References:</h5>
                        {rule.references.map((ref, idx) => (
                          <a key={idx} href={ref} target="_blank" rel="noopener noreferrer">
                            {ref}
                          </a>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}

          {/* Sentinel for Intersection Observer - triggers load more */}
          {visibleCount < sortedMatches.length && (
            <>
              <div ref={sentinelRef} className="scroll-sentinel" />
              <div className="load-more-indicator">
                <span>Showing {Math.min(visibleCount, sortedMatches.length)} of {sortedMatches.length} detection rules</span>
                <button
                  className="load-more-btn"
                  onClick={() => setVisibleCount(prev => Math.min(prev + LOAD_MORE_COUNT, sortedMatches.length))}
                >
                  Load More
                </button>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}
