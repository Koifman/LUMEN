import { useMemo } from 'react';
import { LogEntry } from '../types';
import { getFileColor } from '../lib/fileColors';
import './FileBreakdownStats.css';

interface FileBreakdownStatsProps {
  entries: LogEntry[];
  sourceFiles?: string[];
}

export default function FileBreakdownStats({ entries, sourceFiles }: FileBreakdownStatsProps) {
  const breakdown = useMemo(() => {
    if (!sourceFiles || sourceFiles.length <= 1) {
      return null;
    }

    const stats = new Map<string, number>();

    for (const entry of entries) {
      const file = entry.sourceFile || 'Unknown';
      stats.set(file, (stats.get(file) || 0) + 1);
    }

    return Array.from(stats.entries()).map(([file, count]) => ({
      file,
      count,
      percentage: (count / entries.length) * 100
    })).sort((a, b) => b.count - a.count);
  }, [entries, sourceFiles]);

  if (!breakdown) {
    return null;
  }

  return (
    <div className="file-breakdown-stats">
      <h4>Events by File</h4>
      <div className="breakdown-list">
        {breakdown.map(({ file, count, percentage }) => (
          <div key={file} className="breakdown-item">
            <div className="breakdown-header">
              <div className="file-name-with-color">
                <span
                  className="file-color-indicator"
                  style={{ backgroundColor: getFileColor(file) }}
                />
                <span className="file-name" title={file}>{file}</span>
              </div>
              <span className="event-count">{count.toLocaleString()} events</span>
            </div>
            <div className="breakdown-bar-container">
              <div
                className="breakdown-bar"
                style={{
                  width: `${percentage}%`,
                  background: getFileColor(file)
                }}
              />
            </div>
            <div className="breakdown-percentage">{percentage.toFixed(1)}%</div>
          </div>
        ))}
      </div>
    </div>
  );
}
