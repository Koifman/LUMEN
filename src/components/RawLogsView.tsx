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

    return entries.filter(entry => {
      for (const filter of activeFilters) {
        if (!matchesFilter(entry, filter)) {
          return false;
        }
      }
      return true;
    });
  }, [data.entries, filters, selectedFile]);

  // Add a filter
  const addFilter = (field: string) => {
    if (!filterValue.trim()) {
      setActiveFilterColumn(null);
      return;
    }

    const newFilters = filters.filter(f => f.field !== field);
    newFilters.push({ field, operator: filterOperator, value: filterValue });
    setFilters(newFilters);
    setActiveFilterColumn(null);
    setFilterValue('');
    setFilterOperator('contains');
  };

  // Remove a filter
  const removeFilter = (field: string) => {
    setFilters(filters.filter(f => f.field !== field));
  };

  // Get filter for a field
  const getFilterForField = (field: string) => filters.find(f => f.field === field);

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
              {filters.map(f => (
                <span key={f.field} className="filter-tag">
                  {f.field} {f.operator.replace('_', ' ')} "{f.value}"
                  <button onClick={() => removeFilter(f.field)}>×</button>
                </span>
              ))}
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
                  <div className={`header-cell ${getFilterForField('timestamp') ? 'has-filter' : ''}`} onClick={() => setActiveFilterColumn(activeFilterColumn === 'timestamp' ? null : 'timestamp')}>
                    <span>Timestamp</span>
                    <svg className="filter-icon" viewBox="0 0 24 24" fill="currentColor"><path d="M3 4h18v2H3V4zm3 7h12v2H6v-2zm3 7h6v2H9v-2z"/></svg>
                  </div>
                  <div className={`header-cell ${getFilterForField('computer') ? 'has-filter' : ''}`} onClick={() => setActiveFilterColumn(activeFilterColumn === 'computer' ? null : 'computer')}>
                    <span>Computer</span>
                    <svg className="filter-icon" viewBox="0 0 24 24" fill="currentColor"><path d="M3 4h18v2H3V4zm3 7h12v2H6v-2zm3 7h6v2H9v-2z"/></svg>
                  </div>
                  <div className={`header-cell ${getFilterForField('eventId') ? 'has-filter' : ''}`} onClick={() => setActiveFilterColumn(activeFilterColumn === 'eventId' ? null : 'eventId')}>
                    <span>Event ID</span>
                    <svg className="filter-icon" viewBox="0 0 24 24" fill="currentColor"><path d="M3 4h18v2H3V4zm3 7h12v2H6v-2zm3 7h6v2H9v-2z"/></svg>
                  </div>
                  <div className={`header-cell ${getFilterForField('source') ? 'has-filter' : ''}`} onClick={() => setActiveFilterColumn(activeFilterColumn === 'source' ? null : 'source')}>
                    <span>Source</span>
                    <svg className="filter-icon" viewBox="0 0 24 24" fill="currentColor"><path d="M3 4h18v2H3V4zm3 7h12v2H6v-2zm3 7h6v2H9v-2z"/></svg>
                  </div>
                  <div className={`header-cell ${getFilterForField('message') ? 'has-filter' : ''}`} onClick={() => setActiveFilterColumn(activeFilterColumn === 'message' ? null : 'message')}>
                    <span>Message</span>
                    <svg className="filter-icon" viewBox="0 0 24 24" fill="currentColor"><path d="M3 4h18v2H3V4zm3 7h12v2H6v-2zm3 7h6v2H9v-2z"/></svg>
                  </div>
                  <div className="header-cell action-header">
                    <span>Actions</span>
                  </div>
                </>
              ) : (
                <>
                  <div className={`header-cell ${getFilterForField('timestamp') ? 'has-filter' : ''}`} onClick={() => setActiveFilterColumn(activeFilterColumn === 'timestamp' ? null : 'timestamp')}>
                    <span>Timestamp</span>
                    <svg className="filter-icon" viewBox="0 0 24 24" fill="currentColor"><path d="M3 4h18v2H3V4zm3 7h12v2H6v-2zm3 7h6v2H9v-2z"/></svg>
                  </div>
                  <div className={`header-cell ${getFilterForField('ip') ? 'has-filter' : ''}`} onClick={() => setActiveFilterColumn(activeFilterColumn === 'ip' ? null : 'ip')}>
                    <span>IP Address</span>
                    <svg className="filter-icon" viewBox="0 0 24 24" fill="currentColor"><path d="M3 4h18v2H3V4zm3 7h12v2H6v-2zm3 7h6v2H9v-2z"/></svg>
                  </div>
                  <div className={`header-cell ${getFilterForField('statusCode') ? 'has-filter' : ''}`} onClick={() => setActiveFilterColumn(activeFilterColumn === 'statusCode' ? null : 'statusCode')}>
                    <span>Status</span>
                    <svg className="filter-icon" viewBox="0 0 24 24" fill="currentColor"><path d="M3 4h18v2H3V4zm3 7h12v2H6v-2zm3 7h6v2H9v-2z"/></svg>
                  </div>
                  <div className={`header-cell ${getFilterForField('method') ? 'has-filter' : ''}`} onClick={() => setActiveFilterColumn(activeFilterColumn === 'method' ? null : 'method')}>
                    <span>Method</span>
                    <svg className="filter-icon" viewBox="0 0 24 24" fill="currentColor"><path d="M3 4h18v2H3V4zm3 7h12v2H6v-2zm3 7h6v2H9v-2z"/></svg>
                  </div>
                  <div className={`header-cell ${getFilterForField('path') ? 'has-filter' : ''}`} onClick={() => setActiveFilterColumn(activeFilterColumn === 'path' ? null : 'path')}>
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
                  <button className="filter-close" onClick={() => setActiveFilterColumn(null)}>×</button>
                </div>
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
                  placeholder="Filter value..."
                  value={filterValue}
                  onChange={(e) => setFilterValue(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && addFilter(activeFilterColumn)}
                  autoFocus
                />
                <div className="filter-actions">
                  <button onClick={() => addFilter(activeFilterColumn)}>Apply</button>
                  {getFilterForField(activeFilterColumn) && (
                    <button className="remove-filter" onClick={() => {
                      removeFilter(activeFilterColumn);
                      setActiveFilterColumn(null);
                    }}>Remove</button>
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
