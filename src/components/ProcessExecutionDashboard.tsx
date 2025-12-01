import { useMemo, useState } from 'react';
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

export default function ProcessExecutionDashboard({ entries, onBack }: ProcessExecutionDashboardProps) {
  const [selectedProcess, setSelectedProcess] = useState<string | null>(null);

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

  // Suspicious processes
  const suspiciousProcesses = useMemo(() => {
    return processEvents
      .filter(proc => isSuspiciousPath(proc.image))
      .slice(0, 20);
  }, [processEvents]);

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

      {/* Suspicious Processes Section */}
      {suspiciousProcesses.length > 0 && (
        <div className="suspicious-section">
          <h3>⚠️ Processes from Suspicious Locations</h3>
          <p className="section-desc">
            Processes executed from temporary, download, or public folders
          </p>
          <div className="suspicious-list">
            {suspiciousProcesses.map((proc, idx) => (
              <div key={idx} className="suspicious-item">
                <div className="suspicious-header">
                  <span className="suspicious-name">{getExeName(proc.image)}</span>
                  <span className="suspicious-time">
                    {proc.timestamp.toLocaleString()}
                  </span>
                </div>
                <div className="suspicious-path">{proc.image}</div>
                {proc.commandLine && (
                  <div className="suspicious-cmdline" title={proc.commandLine}>
                    {proc.commandLine.substring(0, 150)}
                    {proc.commandLine.length > 150 ? '...' : ''}
                  </div>
                )}
                <div className="suspicious-meta">
                  <span>User: {proc.user || 'N/A'}</span>
                  <span>Parent: {getExeName(proc.parentImage) || 'N/A'}</span>
                </div>
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
