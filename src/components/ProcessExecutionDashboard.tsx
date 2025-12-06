import { useMemo, useState, useEffect } from 'react';
import {
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import { LogEntry } from '../types';
import { LEGITIMATE_PROCESSES } from '../lib/legitimateProcesses';
import { findClosestMatch } from '../lib/levenshtein';
import './ProcessExecutionDashboard.css';

interface ProcessExecutionDashboardProps {
  entries: LogEntry[];
  onBack: () => void;
}

interface ProcessInfo {
  image: string;
  commandLine: string;
  parentImage: string;
  user: string;
  timestamp: Date;
  eventId: number;
  computer: string;
  processId?: string;
  parentProcessId?: string;
}

// Muted color palette matching the app theme
const COLORS = ['#60a5fa', '#a78bfa', '#f472b6', '#fbbf24', '#4ade80', '#fb923c', '#f87171', '#94a3b8'];

/**
 * Extract process information from EVTX event rawLine
 */
function extractProcessInfo(entry: LogEntry): ProcessInfo | null {
  if (!entry.rawLine && !entry.eventData) return null;

  // Only process Sysmon Event ID 1 (Process Creation) or Security Event ID 4688
  const eventId = entry.eventId;
  if (eventId !== 1 && eventId !== 4688) return null;

  const extractField = (fieldName: string): string => {
    if (entry.eventData && entry.eventData[fieldName]) {
      return entry.eventData[fieldName];
    }

    // Try Data Name format: <Data Name="Image">value</Data>
    const dataRegex = new RegExp(`<Data Name="${fieldName}"[^>]*>([^<]*)</Data>`, 'i');
    const dataMatch = entry.rawLine.match(dataRegex);
    if (dataMatch) return dataMatch[1];

    // Try direct element format: <Image>value</Image>
    const directRegex = new RegExp(`<${fieldName}>([^<]*)</${fieldName}>`, 'i');
    const directMatch = entry.rawLine.match(directRegex);
    if (directMatch) return directMatch[1];

    return '';
  };

  const image = extractField('Image') || extractField('NewProcessName') || '';
  if (!image) return null;

  return {
    image,
    commandLine: extractField('CommandLine') || extractField('ProcessCommandLine') || '',
    parentImage: extractField('ParentImage') || extractField('ParentProcessName') || '',
    user: extractField('User') || extractField('SubjectUserName') || '',
    timestamp: entry.timestamp,
    eventId: eventId || 0,
    computer: entry.computer || '',
    processId: extractField('ProcessId') || extractField('NewProcessId') || '',
    parentProcessId: extractField('ParentProcessId') || '',
  };
}

/**
 * Get the executable name from a full path
 */
function getExeName(fullPath: string): string {
  if (!fullPath) return 'Unknown';
  const parts = fullPath.split('\\');
  return parts[parts.length - 1] || fullPath;
}

/**
 * Categorize process paths
 */
function categorizeProcess(image: string): string {
  const lowerImage = image.toLowerCase();

  if (lowerImage.includes('\\windows\\system32\\')) return 'System32';
  if (lowerImage.includes('\\windows\\syswow64\\')) return 'SysWOW64';
  if (lowerImage.includes('\\program files\\')) return 'Program Files';
  if (lowerImage.includes('\\program files (x86)\\')) return 'Program Files (x86)';
  if (lowerImage.includes('\\users\\') && lowerImage.includes('\\appdata\\')) return 'User AppData';
  if (lowerImage.includes('\\users\\')) return 'User Profile';
  if (lowerImage.includes('\\windows\\')) return 'Windows';
  if (lowerImage.includes('\\temp\\') || lowerImage.includes('\\tmp\\')) return 'Temp Folder';

  return 'Other';
}

/**
 * Check if a process path is suspicious
 */
function isSuspiciousPath(image: string): boolean {
  const lowerImage = image.toLowerCase();

  // Suspicious locations
  const suspiciousPatterns = [
    '\\temp\\',
    '\\tmp\\',
    '\\downloads\\',
    '\\public\\',
    '\\perflogs\\',
    '\\recycler\\',
    '\\$recycle.bin\\',
    'c:\\users\\public\\',
  ];

  return suspiciousPatterns.some(pattern => lowerImage.includes(pattern));
}

/**
 * Default excluded paths for typosquatting analysis
 */
const DEFAULT_EXCLUDED_PATHS = [
  '\\windows\\system32\\',
  '\\windows\\syswow64\\',
  '\\program files\\splunk\\',
  '\\program files\\splunkuniversalforwarder\\',
  '\\program files\\git\\',
  'c:\\program files\\wsl\\',
  'c:\\program files\\bravesoftware\\',
  '\\appdata\\local\\programs\\microsoft vs code\\',
  '\\appdata\\local\\githubdesktop\\',
  '\\appdata\\local\\discord\\',
  '\\appdata\\local\\fluxsoftware\\',
  '\\appdata\\roaming\\zoom\\',
  '\\program files\\nodejs\\',
  '\\microsoft\\windows defender\\',
];

/**
 * Default excluded legitimate processes - these processes will be excluded from the comparison list
 * (i.e., if a process is similar to these, it won't be flagged)
 */
const DEFAULT_EXCLUDED_PROCESSES: string[] = [...LEGITIMATE_PROCESSES];

/**
 * Check if a process path should be excluded from typosquatting analysis
 */
function isExcludedPath(image: string, customExcludedPaths: string[]): boolean {
  const lowerImage = image.toLowerCase();
  return customExcludedPaths.some(pattern => lowerImage.includes(pattern.toLowerCase()));
}

export default function ProcessExecutionDashboard({ entries, onBack }: ProcessExecutionDashboardProps) {
  const [selectedProcess, setSelectedProcess] = useState<string | null>(null);
  const [typosquattingThreshold, setTyposquattingThreshold] = useState<number>(2);
  const [excludedPaths, setExcludedPaths] = useState<string[]>(() => {
    const saved = localStorage.getItem('processAnalysisExcludedPaths');
    return saved ? JSON.parse(saved) : DEFAULT_EXCLUDED_PATHS;
  });
  const [excludedProcesses, setExcludedProcesses] = useState<string[]>(() => {
    const saved = localStorage.getItem('processAnalysisExcludedProcesses');
    return saved ? JSON.parse(saved) : DEFAULT_EXCLUDED_PROCESSES;
  });
  const [showExclusionEditor, setShowExclusionEditor] = useState<boolean>(false);
  const [newExcludedPath, setNewExcludedPath] = useState<string>('');
  const [newExcludedProcess, setNewExcludedProcess] = useState<string>('');

  // Persist excluded paths to localStorage
  useEffect(() => {
    localStorage.setItem('processAnalysisExcludedPaths', JSON.stringify(excludedPaths));
  }, [excludedPaths]);

  // Persist excluded processes to localStorage
  useEffect(() => {
    localStorage.setItem('processAnalysisExcludedProcesses', JSON.stringify(excludedProcesses));
  }, [excludedProcesses]);

  // Extract all process creation events
  const processEvents = useMemo(() => {
    const events: ProcessInfo[] = [];

    for (const entry of entries) {
      const info = extractProcessInfo(entry);
      if (info) {
        events.push(info);
      }
    }

    return events;
  }, [entries]);

  // Top executed processes
  const topProcesses = useMemo(() => {
    const counts = new Map<string, number>();

    for (const proc of processEvents) {
      const name = getExeName(proc.image);
      counts.set(name, (counts.get(name) || 0) + 1);
    }

    return Array.from(counts.entries())
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 15);
  }, [processEvents]);

  // Process location distribution
  const locationDistribution = useMemo(() => {
    const counts = new Map<string, number>();

    for (const proc of processEvents) {
      const category = categorizeProcess(proc.image);
      counts.set(category, (counts.get(category) || 0) + 1);
    }

    return Array.from(counts.entries())
      .map(([location, count]) => ({ location, count }))
      .sort((a, b) => b.count - a.count);
  }, [processEvents]);

  // Parent-child relationships - flat list of relationships with counts
  const parentChildRelationships = useMemo(() => {
    const relationships = new Map<string, number>();

    for (const proc of processEvents) {
      const parent = getExeName(proc.parentImage) || 'Unknown';
      const child = getExeName(proc.image);
      const key = `${parent}|${child}`;
      relationships.set(key, (relationships.get(key) || 0) + 1);
    }

    return Array.from(relationships.entries())
      .map(([key, count]) => {
        const [parent, child] = key.split('|');
        return { parent, child, count };
      })
      .sort((a, b) => b.count - a.count)
      .slice(0, 15);
  }, [processEvents]);

  // Suspicious processes - grouped by process name and parent
  interface SuspiciousMatch {
    processName: string;
    fullPath: string;
    parentProcess: string;
    occurrences: ProcessInfo[];
  }

  const suspiciousProcesses = useMemo(() => {
    const matches = new Map<string, SuspiciousMatch>();

    for (const proc of processEvents) {
      if (!isSuspiciousPath(proc.image)) {
        continue;
      }

      const processName = getExeName(proc.image);
      const parentProcess = getExeName(proc.parentImage) || 'Unknown';
      const key = `${processName}|${parentProcess}`;

      if (matches.has(key)) {
        matches.get(key)!.occurrences.push(proc);
      } else {
        matches.set(key, {
          processName,
          fullPath: proc.image,
          parentProcess,
          occurrences: [proc],
        });
      }
    }

    return Array.from(matches.values())
      .sort((a, b) => b.occurrences.length - a.occurrences.length);
  }, [processEvents]);

  // Typosquatting detection
  interface TyposquattingMatch {
    processName: string;
    fullPath: string;
    legitimateMatch: string;
    distance: number;
    occurrences: ProcessInfo[];
  }

  const typosquattingMatches = useMemo(() => {
    const matches = new Map<string, TyposquattingMatch>();
    const checkedProcesses = new Set<string>(); // Track already-checked process names to avoid redundant checks

    // Use only the processes in excludedProcesses as the comparison list
    const filteredLegitimateProcesses = excludedProcesses;

    for (const proc of processEvents) {
      // Early exit: skip excluded paths (System32, Splunk, Git, VS Code, etc.)
      if (isExcludedPath(proc.image, excludedPaths)) {
        continue;
      }

      const processName = getExeName(proc.image).toLowerCase();

      // If we've already found this process name, just add to occurrences
      if (matches.has(processName)) {
        matches.get(processName)!.occurrences.push(proc);
        continue;
      }

      // If we've already checked this process name and found no match, skip
      if (checkedProcesses.has(processName)) {
        continue;
      }

      // Mark as checked
      checkedProcesses.add(processName);

      // Check for typosquatting against filtered legitimate processes
      const match = findClosestMatch(processName, filteredLegitimateProcesses, typosquattingThreshold);

      if (match) {
        matches.set(processName, {
          processName,
          fullPath: proc.image,
          legitimateMatch: match.match,
          distance: match.distance,
          occurrences: [proc],
        });
      }
    }

    // Convert to array and sort by distance (closer matches are more suspicious)
    return Array.from(matches.values())
      .sort((a, b) => a.distance - b.distance);
  }, [processEvents, typosquattingThreshold, excludedPaths, excludedProcesses]);

  // User activity
  const userActivity = useMemo(() => {
    const counts = new Map<string, number>();

    for (const proc of processEvents) {
      if (proc.user) {
        counts.set(proc.user, (counts.get(proc.user) || 0) + 1);
      }
    }

    return Array.from(counts.entries())
      .map(([user, count]) => ({ user, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
  }, [processEvents]);

  // Process details for selected process
  const selectedProcessDetails = useMemo(() => {
    if (!selectedProcess) return [];

    return processEvents
      .filter(proc => getExeName(proc.image) === selectedProcess)
      .slice(0, 50);
  }, [processEvents, selectedProcess]);

  // No process creation events found
  if (processEvents.length === 0) {
    return (
      <div className="process-dashboard">
        <div className="process-header">
          <div>
            <h1>Process Execution Analysis</h1>
            <p className="subtitle">Sysmon Event ID 1 / Security Event ID 4688</p>
          </div>
          <button className="back-button" onClick={onBack}>
            ← Back
          </button>
        </div>
        <div className="no-data-message">
          <span className="no-data-icon">⚙️</span>
          <h3>No Process Creation Events Found</h3>
          <p>This analysis requires Sysmon Event ID 1 or Windows Security Event ID 4688 logs.</p>
          <p>Make sure your EVTX file contains process creation audit events.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="process-dashboard">
      <div className="process-header">
        <div>
          <h1>Process Execution Analysis</h1>
          <p className="subtitle">
            {processEvents.length.toLocaleString()} process creation events analyzed
          </p>
        </div>
        <button className="back-button" onClick={onBack}>
          ← Back
        </button>
      </div>

      {/* Summary Stats */}
      <div className="process-stats">
        <div className="stat-card">
          <span className="stat-value">{processEvents.length.toLocaleString()}</span>
          <span className="stat-label">Total Executions</span>
        </div>
        <div className="stat-card">
          <span className="stat-value">{new Set(processEvents.map(p => getExeName(p.image))).size}</span>
          <span className="stat-label">Unique Processes</span>
        </div>
        <div className="stat-card">
          <span className="stat-value">{new Set(processEvents.map(p => p.user).filter(Boolean)).size}</span>
          <span className="stat-label">Active Users</span>
        </div>
        <div className="stat-card warning">
          <span className="stat-value">{suspiciousProcesses.length}</span>
          <span className="stat-label">Suspicious Locations</span>
        </div>
        <div className="stat-card warning">
          <span className="stat-value">{typosquattingMatches.length}</span>
          <span className="stat-label">Typosquatting Suspects</span>
        </div>
      </div>

      <div className="process-grid">
        {/* Top Executed Processes */}
        <div className="chart-card">
          <h3>Top Executed Processes</h3>
          <ResponsiveContainer width="100%" height={350}>
            <BarChart data={topProcesses} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="#333" />
              <XAxis type="number" stroke="#999" />
              <YAxis
                type="category"
                dataKey="name"
                stroke="#999"
                width={150}
                tick={{ fontSize: 11 }}
              />
              <Tooltip
                contentStyle={{ background: '#1a1a2e', border: '1px solid #444' }}
              />
              <Bar
                dataKey="count"
                fill="#60a5fa"
                onClick={(entry) => setSelectedProcess(entry.name)}
                cursor="pointer"
              />
            </BarChart>
          </ResponsiveContainer>
          <p className="hint">Click a bar to view process details</p>
        </div>

        {/* Process Location Distribution */}
        <div className="chart-card">
          <h3>Execution Locations</h3>
          <ResponsiveContainer width="100%" height={350}>
            <PieChart>
              <Pie
                data={locationDistribution}
                dataKey="count"
                nameKey="location"
                cx="50%"
                cy="50%"
                outerRadius={120}
                label={({ location, percent }) =>
                  `${location} (${(percent * 100).toFixed(0)}%)`
                }
                labelLine={{ stroke: '#666' }}
              >
                {locationDistribution.map((_, index) => (
                  <Cell key={index} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ background: '#1a1a2e', border: '1px solid #444' }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* User Activity */}
        <div className="chart-card">
          <h3>Process Executions by User</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={userActivity}>
              <CartesianGrid strokeDasharray="3 3" stroke="#333" />
              <XAxis
                dataKey="user"
                stroke="#999"
                angle={-45}
                textAnchor="end"
                height={80}
                tick={{ fontSize: 10 }}
              />
              <YAxis stroke="#999" />
              <Tooltip
                contentStyle={{ background: '#1a1a2e', border: '1px solid #444' }}
              />
              <Bar dataKey="count" fill="#a78bfa" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Parent-Child Relationships Table */}
        <div className="chart-card">
          <h3>Top Process Spawning Patterns</h3>
          <div className="relationship-table">
            <div className="relationship-header">
              <span className="rel-parent">Parent Process</span>
              <span className="rel-arrow">→</span>
              <span className="rel-child">Child Process</span>
              <span className="rel-count">Count</span>
            </div>
            {parentChildRelationships.map((rel, idx) => (
              <div key={idx} className="relationship-row">
                <span className="rel-parent" title={rel.parent}>{rel.parent}</span>
                <span className="rel-arrow">→</span>
                <span className="rel-child" title={rel.child}>{rel.child}</span>
                <span className="rel-count">{rel.count.toLocaleString()}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Typosquatting Detection Section */}
      {typosquattingMatches.length > 0 && (
        <div className="suspicious-section typosquatting-section">
          <div className="section-header-with-controls">
            <div>
              <h3>🔍 Potential Masquerading Detected</h3>
              <p className="section-desc">
                Process names similar to legitimate Windows processes (excluding {excludedPaths.length} paths, comparing against {excludedProcesses.length} processes)
              </p>
            </div>
            <div className="threshold-control">
              <label htmlFor="threshold-slider">
                Distance Threshold: <strong>{typosquattingThreshold}</strong>
              </label>
              <input
                id="threshold-slider"
                type="range"
                min="1"
                max="5"
                value={typosquattingThreshold}
                onChange={(e) => setTyposquattingThreshold(parseInt(e.target.value))}
                className="threshold-slider"
              />
              <span className="threshold-hint">
                (Lower = stricter matching)
              </span>
              <button
                className="exclusion-editor-btn"
                onClick={() => setShowExclusionEditor(!showExclusionEditor)}
              >
                {showExclusionEditor ? 'Hide' : 'Edit'} Exclusions
              </button>
            </div>
          </div>

          {/* Exclusion Editor */}
          {showExclusionEditor && (
            <div className="exclusion-editor">
              <div className="exclusion-section">
                <h4>Excluded Paths ({excludedPaths.length})</h4>
                <div className="exclusion-add">
                  <input
                    type="text"
                    placeholder="e.g., \Program Files\MyApp\"
                    value={newExcludedPath}
                    onChange={(e) => setNewExcludedPath(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' && newExcludedPath.trim()) {
                        setExcludedPaths([...excludedPaths, newExcludedPath.trim()]);
                        setNewExcludedPath('');
                      }
                    }}
                  />
                  <button
                    onClick={() => {
                      if (newExcludedPath.trim()) {
                        setExcludedPaths([...excludedPaths, newExcludedPath.trim()]);
                        setNewExcludedPath('');
                      }
                    }}
                  >
                    Add Path
                  </button>
                </div>
                <div className="exclusion-list">
                  {excludedPaths.map((path, idx) => (
                    <div key={idx} className="exclusion-item">
                      <span>{path}</span>
                      <button
                        className="remove-btn"
                        onClick={() => setExcludedPaths(excludedPaths.filter((_, i) => i !== idx))}
                        title="Remove"
                      >
                        ×
                      </button>
                    </div>
                  ))}
                </div>
              </div>

              <div className="exclusion-section">
                <h4>Legitimate Processes to Compare Against ({excludedProcesses.length})</h4>
                <div className="exclusion-add">
                  <input
                    type="text"
                    placeholder="e.g., svchost.exe"
                    value={newExcludedProcess}
                    onChange={(e) => setNewExcludedProcess(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' && newExcludedProcess.trim()) {
                        setExcludedProcesses([...excludedProcesses, newExcludedProcess.trim().toLowerCase()]);
                        setNewExcludedProcess('');
                      }
                    }}
                  />
                  <button
                    onClick={() => {
                      if (newExcludedProcess.trim()) {
                        setExcludedProcesses([...excludedProcesses, newExcludedProcess.trim().toLowerCase()]);
                        setNewExcludedProcess('');
                      }
                    }}
                  >
                    Add Process
                  </button>
                </div>
                <div className="exclusion-list">
                  {excludedProcesses.map((proc, idx) => (
                    <div key={idx} className="exclusion-item">
                      <span>{proc}</span>
                      <button
                        className="remove-btn"
                        onClick={() => setExcludedProcesses(excludedProcesses.filter((_, i) => i !== idx))}
                        title="Remove from comparison list"
                      >
                        ×
                      </button>
                    </div>
                  ))}
                </div>
              </div>

              <div className="exclusion-actions">
                <button
                  className="reset-btn"
                  onClick={() => {
                    setExcludedPaths(DEFAULT_EXCLUDED_PATHS);
                    setExcludedProcesses(DEFAULT_EXCLUDED_PROCESSES);
                  }}
                >
                  Reset to Defaults
                </button>
              </div>
            </div>
          )}
          <div className="typosquatting-list">
            {typosquattingMatches.map((match, idx) => (
              <div key={idx} className="typosquatting-item">
                <div className="typosquatting-header">
                  <span className="typosquatting-name">{match.processName}</span>
                  <span className="typosquatting-badge">
                    Distance: {match.distance} from "{match.legitimateMatch}"
                  </span>
                </div>
                <div className="typosquatting-path">{match.fullPath}</div>
                <div className="typosquatting-meta">
                  <span>Executions: {match.occurrences.length}</span>
                  <span>First seen: {match.occurrences[0].timestamp.toLocaleString()}</span>
                  {match.occurrences[0].user && (
                    <span>User: {match.occurrences[0].user}</span>
                  )}
                </div>
                {match.occurrences[0].commandLine && (
                  <div className="typosquatting-cmdline" title={match.occurrences[0].commandLine}>
                    <strong>Command:</strong> {match.occurrences[0].commandLine.substring(0, 120)}
                    {match.occurrences[0].commandLine.length > 120 ? '...' : ''}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Suspicious Processes Section */}
      {suspiciousProcesses.length > 0 && (
        <div className="suspicious-section">
          <h3>⚠️ Processes from Suspicious Locations</h3>
          <p className="section-desc">
            Processes executed from temporary, download, or public folders
          </p>
          <div className="suspicious-list">
            {suspiciousProcesses.map((match, idx) => (
              <div key={idx} className="suspicious-item">
                <div className="suspicious-header">
                  <span className="suspicious-name">{match.processName}</span>
                </div>
                <div className="suspicious-path">{match.fullPath}</div>
                <div className="suspicious-meta">
                  <span>Executions: {match.occurrences.length}</span>
                  <span>First seen: {match.occurrences[0].timestamp.toLocaleString()}</span>
                  <span>Parent: {match.parentProcess}</span>
                  {match.occurrences[0].user && (
                    <span>User: {match.occurrences[0].user}</span>
                  )}
                </div>
                {match.occurrences[0].commandLine && (
                  <div className="suspicious-cmdline" title={match.occurrences[0].commandLine}>
                    <strong>Command:</strong> {match.occurrences[0].commandLine.substring(0, 120)}
                    {match.occurrences[0].commandLine.length > 120 ? '...' : ''}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Selected Process Details */}
      {selectedProcess && (
        <div className="process-details-section">
          <div className="details-header">
            <h3>Details: {selectedProcess}</h3>
            <button className="close-btn" onClick={() => setSelectedProcess(null)}>×</button>
          </div>
          <div className="details-count">
            {selectedProcessDetails.length} executions
            {selectedProcessDetails.length === 50 && ' (showing first 50)'}
          </div>
          <div className="details-list">
            {selectedProcessDetails.map((proc, idx) => (
              <div key={idx} className="detail-item">
                <div className="detail-row">
                  <span className="detail-label">Time:</span>
                  <span>{proc.timestamp.toLocaleString()}</span>
                </div>
                <div className="detail-row">
                  <span className="detail-label">Full Path:</span>
                  <span className="detail-path">{proc.image}</span>
                </div>
                {proc.commandLine && (
                  <div className="detail-row">
                    <span className="detail-label">Command:</span>
                    <span className="detail-cmdline">{proc.commandLine}</span>
                  </div>
                )}
                <div className="detail-row">
                  <span className="detail-label">Parent:</span>
                  <span>{proc.parentImage || 'N/A'}</span>
                </div>
                <div className="detail-row">
                  <span className="detail-label">User:</span>
                  <span>{proc.user || 'N/A'}</span>
                </div>
                <div className="detail-row">
                  <span className="detail-label">Computer:</span>
                  <span>{proc.computer || 'N/A'}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
