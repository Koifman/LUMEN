import { useMemo, useState, useCallback } from 'react';
import { SigmaRuleMatch } from '../lib/sigma/types';
import { getSeverityColor } from '../lib/sigmaRules';
import './Timeline.css';

// Filter types
interface TimelineFilters {
  severities: Set<string>;
  searchQuery: string;
  eventIdFilter: string;
  computerFilter: string;
}

/**
 * Format selection definition for tooltip display
 * If matchedPattern is provided, only show that specific pattern value
 */
function formatSelectionForTooltip(
  selection: any,
  selectionName: string,
  fieldName?: string,
  matchedPattern?: string | number | null | (string | number | null)[]
): string {
  if (!selection) return `${selectionName}: (no definition available)`;

  // If we have a matched pattern, show only that specific value
  if (matchedPattern !== undefined && fieldName) {
    // Handle array of patterns (for requireAll conditions)
    if (Array.isArray(matchedPattern)) {
      let yaml = `${selectionName}:\n  ${fieldName}:\n`;
      matchedPattern.forEach(pattern => {
        yaml += `    - '${pattern}'\n`;
      });
      return yaml.trim();
    }
    // Single pattern
    return `${selectionName}:\n  ${fieldName}: '${matchedPattern}'`;
  }

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

interface TimelineProps {
  matches: Map<string, SigmaRuleMatch[]>;
  onBack: () => void;
}

interface TimelineEvent {
  timestamp: Date;
  rule: {
    id: string;
    title: string;
    level: string;
  };
  event: any;
  match: SigmaRuleMatch;
}

interface AggregatedBucket {
  startTime: Date;
  endTime: Date;
  events: TimelineEvent[];
  bySeverity: Record<string, number>;
}

type ZoomLevel = 'minute' | 'hour' | 'day';

export default function Timeline({ matches, onBack }: TimelineProps) {
  const [zoomLevel, setZoomLevel] = useState<ZoomLevel>('hour');
  const [selectedBucket, setSelectedBucket] = useState<AggregatedBucket | null>(null);
  const [expandedEvents, setExpandedEvents] = useState<Set<number>>(new Set());

  // Filter state
  const [filters, setFilters] = useState<TimelineFilters>({
    severities: new Set(['critical', 'high', 'medium', 'low', 'informational']),
    searchQuery: '',
    eventIdFilter: '',
    computerFilter: ''
  });
  const [showFilters, setShowFilters] = useState(false);

  // Toggle severity filter
  const toggleSeverity = useCallback((severity: string) => {
    setFilters(prev => {
      const newSeverities = new Set(prev.severities);
      if (newSeverities.has(severity)) {
        newSeverities.delete(severity);
      } else {
        newSeverities.add(severity);
      }
      return { ...prev, severities: newSeverities };
    });
  }, []);

  // Clear all filters
  const clearFilters = useCallback(() => {
    setFilters({
      severities: new Set(['critical', 'high', 'medium', 'low', 'informational']),
      searchQuery: '',
      eventIdFilter: '',
      computerFilter: ''
    });
  }, []);

  // Check if any filters are active
  const hasActiveFilters = useMemo(() => {
    return filters.severities.size < 5 ||
           filters.searchQuery !== '' ||
           filters.eventIdFilter !== '' ||
           filters.computerFilter !== '';
  }, [filters]);

  // Flatten all matches into timeline events
  const allTimelineEvents = useMemo(() => {
    const events: TimelineEvent[] = [];

    for (const [, ruleMatches] of matches) {
      for (const match of ruleMatches) {
        const eventData = match.event as any;
        const timestamp = eventData.timestamp || match.timestamp || new Date();

        events.push({
          timestamp: timestamp instanceof Date ? timestamp : new Date(timestamp),
          rule: {
            id: match.rule.id,
            title: match.rule.title,
            level: match.rule.level || 'medium'
          },
          event: eventData,
          match
        });
      }
    }

    // Sort by timestamp
    return events.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
  }, [matches]);

  // Apply filters to timeline events
  const timelineEvents = useMemo(() => {
    return allTimelineEvents.filter(event => {
      // Severity filter
      if (!filters.severities.has(event.rule.level)) {
        return false;
      }

      // Search query filter (matches rule title)
      if (filters.searchQuery) {
        const query = filters.searchQuery.toLowerCase();
        const matchesSearch = event.rule.title.toLowerCase().includes(query) ||
                             event.rule.id.toLowerCase().includes(query);
        if (!matchesSearch) return false;
      }

      // Event ID filter
      if (filters.eventIdFilter) {
        const eventId = event.event.eventId || event.event.EventID;
        if (!eventId || !String(eventId).includes(filters.eventIdFilter)) {
          return false;
        }
      }

      // Computer filter
      if (filters.computerFilter) {
        const computer = event.event.computer || event.event.Computer || '';
        if (!computer.toLowerCase().includes(filters.computerFilter.toLowerCase())) {
          return false;
        }
      }

      return true;
    });
  }, [allTimelineEvents, filters]);

  // Aggregate events into time buckets based on zoom level
  const aggregatedBuckets = useMemo(() => {
    if (timelineEvents.length === 0) return [];

    const buckets: AggregatedBucket[] = [];
    const bucketSize = zoomLevel === 'minute' ? 60000 : zoomLevel === 'hour' ? 3600000 : 86400000;

    let currentBucket: AggregatedBucket | null = null;

    for (const event of timelineEvents) {
      const bucketStart = Math.floor(event.timestamp.getTime() / bucketSize) * bucketSize;

      if (!currentBucket || currentBucket.startTime.getTime() !== bucketStart) {
        if (currentBucket) {
          buckets.push(currentBucket);
        }
        currentBucket = {
          startTime: new Date(bucketStart),
          endTime: new Date(bucketStart + bucketSize),
          events: [],
          bySeverity: { critical: 0, high: 0, medium: 0, low: 0, informational: 0 }
        };
      }

      currentBucket.events.push(event);
      const severity = event.rule.level || 'medium';
      currentBucket.bySeverity[severity] = (currentBucket.bySeverity[severity] || 0) + 1;
    }

    if (currentBucket) {
      buckets.push(currentBucket);
    }

    return buckets;
  }, [timelineEvents, zoomLevel]);

  // Calculate max events for scaling bars
  const maxEvents = useMemo(() => {
    return Math.max(...aggregatedBuckets.map(b => b.events.length), 1);
  }, [aggregatedBuckets]);

  // Format time for bucket label
  const formatBucketTime = (date: Date): string => {
    if (zoomLevel === 'day') {
      return date.toLocaleDateString();
    } else if (zoomLevel === 'hour') {
      return date.toLocaleString(undefined, {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
    } else {
      return date.toLocaleTimeString();
    }
  };

  // Stats
  const stats = useMemo(() => {
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
    for (const event of timelineEvents) {
      const severity = event.rule.level || 'medium';
      bySeverity[severity as keyof typeof bySeverity]++;
    }

    const uniqueRules = new Set(timelineEvents.map(e => e.rule.id)).size;
    const timeRange = timelineEvents.length > 0
      ? {
          start: timelineEvents[0].timestamp,
          end: timelineEvents[timelineEvents.length - 1].timestamp
        }
      : null;

    return { total: timelineEvents.length, bySeverity, uniqueRules, timeRange };
  }, [timelineEvents]);

  const toggleEventExpanded = (index: number) => {
    const newExpanded = new Set(expandedEvents);
    if (newExpanded.has(index)) {
      newExpanded.delete(index);
    } else {
      newExpanded.add(index);
    }
    setExpandedEvents(newExpanded);
  };

  return (
    <div className="timeline-page">
      <header className="timeline-header">
        <div>
          <h1>Detection Timeline</h1>
          <p className="timeline-subtitle">
            {stats.total} detections from {stats.uniqueRules} rules
            {stats.timeRange && (
              <> • {stats.timeRange.start.toLocaleString()} to {stats.timeRange.end.toLocaleString()}</>
            )}
          </p>
        </div>
        <button className="back-button" onClick={onBack}>
          ← Back to Analysis
        </button>
      </header>

      {/* Summary Stats */}
      <div className="timeline-stats">
        <div className="stat-pill critical">
          <span className="stat-count">{stats.bySeverity.critical}</span>
          <span className="stat-label">Critical</span>
        </div>
        <div className="stat-pill high">
          <span className="stat-count">{stats.bySeverity.high}</span>
          <span className="stat-label">High</span>
        </div>
        <div className="stat-pill medium">
          <span className="stat-count">{stats.bySeverity.medium}</span>
          <span className="stat-label">Medium</span>
        </div>
        <div className="stat-pill low">
          <span className="stat-count">{stats.bySeverity.low}</span>
          <span className="stat-label">Low</span>
        </div>
      </div>

      {/* Filter Controls */}
      <div className="timeline-controls">
        <div className="zoom-controls">
          <span>Aggregate by:</span>
          <button
            className={zoomLevel === 'minute' ? 'active' : ''}
            onClick={() => setZoomLevel('minute')}
          >
            Minute
          </button>
          <button
            className={zoomLevel === 'hour' ? 'active' : ''}
            onClick={() => setZoomLevel('hour')}
          >
            Hour
          </button>
          <button
            className={zoomLevel === 'day' ? 'active' : ''}
            onClick={() => setZoomLevel('day')}
          >
            Day
          </button>
        </div>

        <button
          className={`filter-toggle-btn ${showFilters ? 'active' : ''} ${hasActiveFilters ? 'has-filters' : ''}`}
          onClick={() => setShowFilters(!showFilters)}
        >
          🔍 Filters {hasActiveFilters && `(${allTimelineEvents.length - timelineEvents.length} hidden)`}
        </button>
      </div>

      {/* Filter Panel */}
      {showFilters && (
        <div className="timeline-filters">
          <div className="filter-section">
            <label>Severity:</label>
            <div className="severity-toggles">
              {['critical', 'high', 'medium', 'low', 'informational'].map(severity => (
                <button
                  key={severity}
                  className={`severity-toggle ${severity} ${filters.severities.has(severity) ? 'active' : ''}`}
                  onClick={() => toggleSeverity(severity)}
                >
                  {severity.charAt(0).toUpperCase() + severity.slice(1)}
                </button>
              ))}
            </div>
          </div>

          <div className="filter-section">
            <label>Search Rules:</label>
            <input
              type="text"
              placeholder="Search rule name or ID..."
              value={filters.searchQuery}
              onChange={(e) => setFilters(prev => ({ ...prev, searchQuery: e.target.value }))}
              className="filter-input"
            />
          </div>

          <div className="filter-section">
            <label>Event ID:</label>
            <input
              type="text"
              placeholder="Filter by Event ID..."
              value={filters.eventIdFilter}
              onChange={(e) => setFilters(prev => ({ ...prev, eventIdFilter: e.target.value }))}
              className="filter-input"
            />
          </div>

          <div className="filter-section">
            <label>Computer:</label>
            <input
              type="text"
              placeholder="Filter by computer name..."
              value={filters.computerFilter}
              onChange={(e) => setFilters(prev => ({ ...prev, computerFilter: e.target.value }))}
              className="filter-input"
            />
          </div>

          {hasActiveFilters && (
            <button className="clear-filters-btn" onClick={clearFilters}>
              Clear All Filters
            </button>
          )}
        </div>
      )}

      {/* Timeline Visualization */}
      <div className="timeline-chart">
        {aggregatedBuckets.length === 0 ? (
          <div className="no-data">No detection events to display</div>
        ) : (
          <div className="timeline-bars">
            {aggregatedBuckets.map((bucket, idx) => (
              <div
                key={idx}
                className={`timeline-bar-container ${selectedBucket === bucket ? 'selected' : ''}`}
                onClick={() => setSelectedBucket(selectedBucket === bucket ? null : bucket)}
              >
                <div className="timeline-bar-wrapper">
                  <div
                    className="timeline-bar"
                    style={{ height: `${(bucket.events.length / maxEvents) * 100}%` }}
                  >
                    {/* Stacked severity segments */}
                    {bucket.bySeverity.critical > 0 && (
                      <div
                        className="bar-segment critical"
                        style={{
                          height: `${(bucket.bySeverity.critical / bucket.events.length) * 100}%`
                        }}
                      />
                    )}
                    {bucket.bySeverity.high > 0 && (
                      <div
                        className="bar-segment high"
                        style={{
                          height: `${(bucket.bySeverity.high / bucket.events.length) * 100}%`
                        }}
                      />
                    )}
                    {bucket.bySeverity.medium > 0 && (
                      <div
                        className="bar-segment medium"
                        style={{
                          height: `${(bucket.bySeverity.medium / bucket.events.length) * 100}%`
                        }}
                      />
                    )}
                    {bucket.bySeverity.low > 0 && (
                      <div
                        className="bar-segment low"
                        style={{
                          height: `${(bucket.bySeverity.low / bucket.events.length) * 100}%`
                        }}
                      />
                    )}
                  </div>
                  <div className="bar-count">{bucket.events.length}</div>
                </div>
                <div className="timeline-label">{formatBucketTime(bucket.startTime)}</div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Selected Bucket Details */}
      {selectedBucket && (
        <div className="bucket-details">
          <div className="bucket-details-header">
            <h3>
              Events from {formatBucketTime(selectedBucket.startTime)}
              <span className="event-count">({selectedBucket.events.length} events)</span>
            </h3>
            <button className="close-btn" onClick={() => setSelectedBucket(null)}>×</button>
          </div>
          <div className="bucket-events">
            {selectedBucket.events.slice(0, 100).map((event, idx) => (
              <div
                key={idx}
                className={`bucket-event ${expandedEvents.has(idx) ? 'expanded' : ''}`}
                style={{ borderLeftColor: getSeverityColor(event.rule.level) }}
              >
                <div
                  className="event-summary"
                  onClick={() => toggleEventExpanded(idx)}
                >
                  <span className="event-time">
                    {event.timestamp.toLocaleTimeString()}
                  </span>
                  <span
                    className="event-severity"
                    style={{ backgroundColor: getSeverityColor(event.rule.level) }}
                  >
                    {event.rule.level.toUpperCase()}
                  </span>
                  <span className="event-title">{event.rule.title}</span>
                  <span className="expand-icon">{expandedEvents.has(idx) ? '▼' : '▶'}</span>
                </div>
                {expandedEvents.has(idx) && (
                  <div className="event-details">
                    <div className="detail-row">
                      <span className="detail-label">Computer:</span>
                      <span>{event.event.computer || event.event.Computer || 'N/A'}</span>
                    </div>
                    <div className="detail-row">
                      <span className="detail-label">Event ID:</span>
                      <span>{event.event.eventId || event.event.EventID || 'N/A'}</span>
                    </div>
                    <div className="detail-row">
                      <span className="detail-label">Source:</span>
                      <span>{event.event.source || event.event.Provider || 'N/A'}</span>
                    </div>
                    {/* Matched Fields Section */}
                    {(() => {
                      const allFieldMatches: Array<{
                        field: string;
                        value: any;
                        selection: string;
                        selectionDef?: any;
                        modifier?: string;
                        matchedPattern?: string | number | null | (string | number | null)[];
                      }> = [];

                      if (event.match.selectionMatches) {
                        for (const selMatch of event.match.selectionMatches) {
                          // Get the selection definition from compiled rule
                          let selectionDef;
                          if (event.match.compiledRule && event.match.compiledRule.selections) {
                            const selection = event.match.compiledRule.selections.get(selMatch.selection);
                            selectionDef = selection?.originalDefinition;
                          }

                          if (selMatch.fieldMatches) {
                            for (const fm of selMatch.fieldMatches) {
                              if (fm.matched) {
                                allFieldMatches.push({
                                  field: fm.field,
                                  value: fm.value,
                                  selection: selMatch.selection,
                                  selectionDef: selectionDef,
                                  modifier: fm.modifier,
                                  matchedPattern: fm.matchedPattern
                                });
                              }
                            }
                          }
                        }
                      }

                      if (allFieldMatches.length === 0) return null;

                      return (
                        <div className="matched-fields">
                          <div className="matched-fields-header">
                            Matched Fields:
                            <span style={{ fontSize: '0.7rem', fontWeight: 'normal', marginLeft: '0.5rem', color: 'var(--text-dim)' }}>
                              (Tooltip hover shows only the exact values that a condition matched against and NOT the entire list)
                            </span>
                          </div>
                          {allFieldMatches.map((fm, fmIdx) => (
                            <div key={fmIdx} className="field-match">
                              <div className="field-match-header">
                                <span className="field-name">{fm.field}</span>
                                {fm.modifier && fm.modifier !== 'equals' && (
                                  <span className="field-modifier">{fm.modifier}</span>
                                )}
                                <span className="field-selection-wrapper">
                                  <span className="field-selection">
                                    {fm.selection}
                                  </span>
                                  {fm.selectionDef && (
                                    <span className="field-selection-tooltip">
                                      <pre>{formatSelectionForTooltip(fm.selectionDef, fm.selection, fm.field, fm.matchedPattern)}</pre>
                                    </span>
                                  )}
                                </span>
                              </div>
                              <div className="field-value">
                                {String(fm.value).substring(0, 200)}
                                {String(fm.value).length > 200 ? '...' : ''}
                              </div>
                            </div>
                          ))}
                        </div>
                      );
                    })()}
                  </div>
                )}
              </div>
            ))}
            {selectedBucket.events.length > 100 && (
              <div className="more-events">
                +{selectedBucket.events.length - 100} more events
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
