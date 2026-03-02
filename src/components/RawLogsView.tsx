import { useMemo, useState } from 'react';
import { ParsedData, LogEntry } from '../types';
import FileFilter from './FileFilter';
import FileBreakdownStats from './FileBreakdownStats';
import { getFileColor } from '../lib/fileColors';
import { EventDetailsModal } from './EventDetailsModal';
import './Dashboard.css';

interface RawLogsViewProps {
  data: ParsedData;
  filename: string;
  onBack: () => void;
}

type FilterOperator = 'equals' | 'contains' | 'not_equals' | 'not_contains';
type FilterLogic = 'OR' | 'AND';

interface ColumnFilter {
  field: string;
  operator: FilterOperator;
  value: string;
}

// Helper function to get field value
function getFieldValue(entry: LogEntry, field: string): string {
  switch (field) {
    case 'timestamp':
      return entry.timestamp.toISOString();
    case 'computer':
      return entry.computer || '';
    case 'eventId':
      return String(entry.eventId || '');
    case 'source':
      return entry.source || '';
    case 'message':
      return entry.message || '';
    case 'ip':
      return entry.ip || '';
    case 'statusCode':
      return String(entry.statusCode || '');
    case 'method':
      return entry.method || '';
    case 'path':
      return entry.path || '';
    case 'sourceFile':
      return entry.sourceFile || '';
    default:
      return '';
  }
}

// Filter matching function
function matchesFilter(entry: LogEntry, filter: ColumnFilter): boolean {
  const fieldValue = getFieldValue(entry, filter.field).toLowerCase();
  const filterVal = filter.value.toLowerCase();

  switch (filter.operator) {
    case 'equals':
      return fieldValue === filterVal;
    case 'contains':
      return fieldValue.includes(filterVal);
    case 'not_equals':
      return fieldValue !== filterVal;
    case 'not_contains':
      return !fieldValue.includes(filterVal);
    default:
      return true;
  }
}

export default function RawLogsView({ data, filename, onBack }: RawLogsViewProps) {
  const [filters, setFilters] = useState<ColumnFilter[]>([]);
  const [activeFilterColumn, setActiveFilterColumn] = useState<string | null>(null);
  const [filterValue, setFilterValue] = useState('');
  const [filterOperator, setFilterOperator] = useState<FilterOperator>('contains');
  const [selectedFile, setSelectedFile] = useState<string | null>(null);
  const [filterLogic, setFilterLogic] = useState<FilterLogic>('OR');

  // Modal state for viewing raw event
  const [selectedEvent, setSelectedEvent] = useState<LogEntry | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);

  // Filtered entries
  const filteredEntries = useMemo(() => {
    let entries = data.entries;

    // Filter by selected file first
    if (selectedFile) {
      entries = entries.filter(entry => entry.sourceFile === selectedFile);
    }

    // Then apply column filters
    const activeFilters = filters.filter(f => f.value);

    if (activeFilters.length === 0) {
      return entries;
    }

    // Group filters by field — logic between same-field filters is user-selectable
    const filtersByField = new Map<string, ColumnFilter[]>();
    for (const filter of activeFilters) {
      const existing = filtersByField.get(filter.field) || [];
      existing.push(filter);
      filtersByField.set(filter.field, existing);
    }

    return entries.filter(entry => {
      // AND between different fields: entry must satisfy every field group
      for (const fieldFilters of filtersByField.values()) {
        if (filterLogic === 'OR') {
          // OR: entry matches if ANY filter in this field matches
          if (!fieldFilters.some(filter => matchesFilter(entry, filter))) {
            return false;
          }
        } else {
          // AND: entry must match ALL filters in this field
          if (!fieldFilters.every(filter => matchesFilter(entry, filter))) {
            return false;
          }
        }
      }
      return true;
    });
  }, [data.entries, filters, selectedFile, filterLogic]);

  // Add a filter (allows multiple filters per field)
  const addFilter = (field: string) => {
    if (!filterValue.trim()) {
      setActiveFilterColumn(null);
      return;
    }

    // Check for duplicate: same field + operator + value
    const isDuplicate = filters.some(
      f => f.field === field && f.operator === filterOperator && f.value.toLowerCase() === filterValue.trim().toLowerCase()
    );
    if (!isDuplicate) {
      setFilters([...filters, { field, operator: filterOperator, value: filterValue.trim() }]);
    }
    setFilterValue('');
    setFilterOperator('contains');
  };

  // Remove a specific filter by index
  const removeFilter = (index: number) => {
    setFilters(filters.filter((_, i) => i !== index));
  };

  // Remove all filters for a field
  const removeFieldFilters = (field: string) => {
    setFilters(filters.filter(f => f.field !== field));
  };

  // Get all filters for a field
  const getFiltersForField = (field: string) => filters.filter(f => f.field === field);

  // Check if field has any filters
  const hasFilterForField = (field: string) => filters.some(f => f.field === field);

  // Handle opening event details modal
  const handleViewEvent = (entry: LogEntry) => {
    setSelectedEvent(entry);
    setIsModalOpen(true);
  };

  return (
    <div className="dashboard">
      <header className="dashboard-header">
        <div>
          <div className="logo-container">
            <h1>LUMEN</h1>
            <span style={{ fontSize: '2rem' }}>🔆</span>
          </div>
          <p className="tagline">Your EVTX companion</p>
          <p className="filename">
            {filename} • {data.parsedLines} / {data.totalLines} lines parsed • Format: {data.format}
          </p>
        </div>
        <div className="header-buttons">
          <button className="timeline-button" onClick={onBack}>
            ← Back to Selection
          </button>
        </div>
      </header>

      {/* Raw Logs Section */}
      <div className="raw-logs-section">
        <div className="chart-card log-viewer">
          <h3>Raw Logs ({filteredEntries.length.toLocaleString()} entries)</h3>

          {/* File Breakdown Stats */}
          <FileBreakdownStats
            entries={data.entries}
            sourceFiles={data.sourceFiles}
          />

          {/* File Filter */}
          <FileFilter
            sourceFiles={data.sourceFiles}
            selectedFile={selectedFile}
            onFileSelect={setSelectedFile}
          />

          {/* Active Filters Display */}
          {filters.length > 0 && (
            <div className="active-filters">
              {filters.map((f, idx) => (
                <span key={`${f.field}-${f.operator}-${f.value}-${idx}`} className="filter-tag">
                  {f.field} {f.operator.replace('_', ' ')} "{f.value}"
                  <button onClick={() => removeFilter(idx)}>×</button>
                </span>
              ))}
              {/* Show logic toggle only when there are multiple filters on any single field */}
              {Array.from(new Map<string, number>(
                filters.reduce((acc, f) => {
                  acc.set(f.field, (acc.get(f.field) || 0) + 1);
                  return acc;
                }, new Map<string, number>())
              ).values()).some(count => count > 1) && (
                <button
                  className={`filter-logic-toggle ${filterLogic === 'AND' ? 'logic-and' : 'logic-or'}`}
                  onClick={() => setFilterLogic(filterLogic === 'OR' ? 'AND' : 'OR')}
                  title={filterLogic === 'OR'
                    ? 'OR mode: matches any filter per field. Click to switch to AND.'
                    : 'AND mode: must match all filters per field. Click to switch to OR.'}
                >
                  {filterLogic}
                </button>
              )}
              <button className="clear-all-filters" onClick={() => setFilters([])}>
                Clear All
              </button>
            </div>
          )}

          <div className="log-table-container">
            {/* Column Headers */}
            <div className={`log-header ${data.format === 'evtx' ? 'evtx-header' : ''}`}>
              {data.format === 'evtx' ? (
                <>
                  <div className={`header-cell ${hasFilterForField('timestamp') ? 'has-filter' : ''}`} onClick={() => setActiveFilterColumn(activeFilterColumn === 'timestamp' ? null : 'timestamp')}>
                    <span>Timestamp</span>
                    <svg className="filter-icon" viewBox="0 0 24 24" fill="currentColor"><path d="M3 4h18v2H3V4zm3 7h12v2H6v-2zm3 7h6v2H9v-2z"/></svg>
                  </div>
                  <div className={`header-cell ${hasFilterForField('computer') ? 'has-filter' : ''}`} onClick={() => setActiveFilterColumn(activeFilterColumn === 'computer' ? null : 'computer')}>
                    <span>Computer</span>
                    <svg className="filter-icon" viewBox="0 0 24 24" fill="currentColor"><path d="M3 4h18v2H3V4zm3 7h12v2H6v-2zm3 7h6v2H9v-2z"/></svg>
                  </div>
                  <div className={`header-cell ${hasFilterForField('eventId') ? 'has-filter' : ''}`} onClick={() => setActiveFilterColumn(activeFilterColumn === 'eventId' ? null : 'eventId')}>
                    <span>Event ID</span>
                    <svg className="filter-icon" viewBox="0 0 24 24" fill="currentColor"><path d="M3 4h18v2H3V4zm3 7h12v2H6v-2zm3 7h6v2H9v-2z"/></svg>
                  </div>
                  <div className={`header-cell ${hasFilterForField('source') ? 'has-filter' : ''}`} onClick={() => setActiveFilterColumn(activeFilterColumn === 'source' ? null : 'source')}>
                    <span>Source</span>
                    <svg className="filter-icon" viewBox="0 0 24 24" fill="currentColor"><path d="M3 4h18v2H3V4zm3 7h12v2H6v-2zm3 7h6v2H9v-2z"/></svg>
                  </div>
                  <div className={`header-cell ${hasFilterForField('message') ? 'has-filter' : ''}`} onClick={() => setActiveFilterColumn(activeFilterColumn === 'message' ? null : 'message')}>
                    <span>Message</span>
                    <svg className="filter-icon" viewBox="0 0 24 24" fill="currentColor"><path d="M3 4h18v2H3V4zm3 7h12v2H6v-2zm3 7h6v2H9v-2z"/></svg>
                  </div>
                  <div className="header-cell action-header">
                    <span>Actions</span>
                  </div>
                </>
              ) : (
                <>
                  <div className={`header-cell ${hasFilterForField('timestamp') ? 'has-filter' : ''}`} onClick={() => setActiveFilterColumn(activeFilterColumn === 'timestamp' ? null : 'timestamp')}>
                    <span>Timestamp</span>
                    <svg className="filter-icon" viewBox="0 0 24 24" fill="currentColor"><path d="M3 4h18v2H3V4zm3 7h12v2H6v-2zm3 7h6v2H9v-2z"/></svg>
                  </div>
                  <div className={`header-cell ${hasFilterForField('ip') ? 'has-filter' : ''}`} onClick={() => setActiveFilterColumn(activeFilterColumn === 'ip' ? null : 'ip')}>
                    <span>IP Address</span>
                    <svg className="filter-icon" viewBox="0 0 24 24" fill="currentColor"><path d="M3 4h18v2H3V4zm3 7h12v2H6v-2zm3 7h6v2H9v-2z"/></svg>
                  </div>
                  <div className={`header-cell ${hasFilterForField('statusCode') ? 'has-filter' : ''}`} onClick={() => setActiveFilterColumn(activeFilterColumn === 'statusCode' ? null : 'statusCode')}>
                    <span>Status</span>
                    <svg className="filter-icon" viewBox="0 0 24 24" fill="currentColor"><path d="M3 4h18v2H3V4zm3 7h12v2H6v-2zm3 7h6v2H9v-2z"/></svg>
                  </div>
                  <div className={`header-cell ${hasFilterForField('method') ? 'has-filter' : ''}`} onClick={() => setActiveFilterColumn(activeFilterColumn === 'method' ? null : 'method')}>
                    <span>Method</span>
                    <svg className="filter-icon" viewBox="0 0 24 24" fill="currentColor"><path d="M3 4h18v2H3V4zm3 7h12v2H6v-2zm3 7h6v2H9v-2z"/></svg>
                  </div>
                  <div className={`header-cell ${hasFilterForField('path') ? 'has-filter' : ''}`} onClick={() => setActiveFilterColumn(activeFilterColumn === 'path' ? null : 'path')}>
                    <span>Path</span>
                    <svg className="filter-icon" viewBox="0 0 24 24" fill="currentColor"><path d="M3 4h18v2H3V4zm3 7h12v2H6v-2zm3 7h6v2H9v-2z"/></svg>
                  </div>
                  <div className="header-cell action-header">
                    <span>Actions</span>
                  </div>
                </>
              )}
            </div>

            {/* Filter Popup */}
            {activeFilterColumn && (
              <div className="filter-popup">
                <div className="filter-popup-header">
                  Filter: {activeFilterColumn}
                  <button className="filter-close" onClick={() => { setActiveFilterColumn(null); setFilterValue(''); setFilterOperator('contains'); }}>×</button>
                </div>
                {/* Existing filters for this field */}
                {getFiltersForField(activeFilterColumn).length > 0 && (
                  <div className="filter-existing">
                    {getFiltersForField(activeFilterColumn).map((f, idx) => {
                      const globalIdx = filters.indexOf(f);
                      return (
                        <div key={idx} className="filter-existing-item">
                          <span className="filter-existing-text">
                            {f.operator.replace('_', ' ')} "{f.value}"
                          </span>
                          <button className="filter-existing-remove" onClick={() => removeFilter(globalIdx)}>×</button>
                        </div>
                      );
                    })}
                  </div>
                )}
                <select
                  value={filterOperator}
                  onChange={(e) => setFilterOperator(e.target.value as FilterOperator)}
                >
                  <option value="contains">Contains</option>
                  <option value="equals">Equals</option>
                  <option value="not_contains">Does not contain</option>
                  <option value="not_equals">Does not equal</option>
                </select>
                <input
                  type="text"
                  placeholder="Add filter value..."
                  value={filterValue}
                  onChange={(e) => setFilterValue(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && addFilter(activeFilterColumn)}
                  autoFocus
                />
                <div className="filter-actions">
                  <button onClick={() => addFilter(activeFilterColumn)}>Add Filter</button>
                  {hasFilterForField(activeFilterColumn) && (
                    <button className="remove-filter" onClick={() => {
                      removeFieldFilters(activeFilterColumn);
                    }}>Remove All</button>
                  )}
                </div>
              </div>
            )}

            {/* Log Entries */}
            <div className="log-entries">
              {filteredEntries.slice(0, 100).map((entry, idx) => (
                <div
                  key={idx}
                  className={`log-entry ${data.format === 'evtx' ? 'evtx-entry' : ''}`}
                  style={entry.sourceFile && data.sourceFiles && data.sourceFiles.length > 1 ? {
                    borderLeft: `3px solid ${getFileColor(entry.sourceFile)}`
                  } : undefined}
                >
                  <span className="log-time">{entry.timestamp.toLocaleString()}</span>
                  {data.format === 'evtx' ? (
                    <>
                      <span className="log-computer">{entry.computer || 'N/A'}</span>
                      <span className="log-event-id">{entry.eventId}</span>
                      <span className="log-source">{entry.source}</span>
                      <span className="log-message" title={entry.message}>
                        {entry.message || 'No message'}
                      </span>
                      <span className="log-action">
                        <button
                          className="view-details-btn"
                          onClick={() => handleViewEvent(entry)}
                          title="View complete event details"
                        >
                          👁️
                        </button>
                      </span>
                    </>
                  ) : (
                    <>
                      <span className="log-ip">{entry.ip}</span>
                      <span className={`log-status status-${Math.floor(entry.statusCode / 100)}xx`}>
                        {entry.statusCode}
                      </span>
                      <span className="log-method">{entry.method}</span>
                      <span className="log-path">{entry.path}</span>
                      <span className="log-action">
                        <button
                          className="view-details-btn"
                          onClick={() => handleViewEvent(entry)}
                          title="View complete event details"
                        >
                          👁️
                        </button>
                      </span>
                    </>
                  )}
                </div>
              ))}
              {filteredEntries.length > 100 && (
                <div className="log-entry-more">
                  ... and {filteredEntries.length - 100} more entries
                </div>
              )}
              {filteredEntries.length === 0 && (
                <div className="log-entry-more">
                  No entries match the current filters
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Event Details Modal */}
      <EventDetailsModal
        event={selectedEvent}
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
      />
    </div>
  );
}
