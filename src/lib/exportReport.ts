// Export Analysis Report functionality
import { ParsedData } from '../types';
import { SigmaRuleMatch } from './sigma/types';
import { CorrelatedChain, correlateEvents } from './correlationEngine';

export interface ReportOptions {
  includeExecutiveSummary: boolean;
  includeSigmaMatches: boolean;
  includeCorrelationChains: boolean;
  includeEventStatistics: boolean;
  includeIOCs: boolean;
  includeTimeline: boolean;
  format: 'html' | 'markdown' | 'json';
}

export interface ReportData {
  filename: string;
  generatedAt: Date;
  platform: string | null;
  data: ParsedData;
  sigmaMatches: Map<string, SigmaRuleMatch[]>;
  options: ReportOptions;
}

// Field match details for export
interface ExtractedFieldMatch {
  field: string;
  value: any;
  modifier?: string;
  matchedPattern?: string | number | null | (string | number | null)[];
  selection: string;
}

// Essential event data for export
interface EssentialEventData {
  eventId?: number;
  computer?: string;
  timestamp: string;
  source?: string;
  sourceFile?: string;
  level?: string;
}

// Generate full analysis report
export function generateReport(reportData: ReportData): string {
  const { format } = reportData.options;

  switch (format) {
    case 'html':
      return generateHTMLReport(reportData);
    case 'markdown':
      return generateMarkdownReport(reportData);
    case 'json':
      return generateJSONReport(reportData);
    default:
      return generateHTMLReport(reportData);
  }
}

// Generate HTML report
function generateHTMLReport(reportData: ReportData): string {
  const { filename, generatedAt, platform, data, sigmaMatches, options } = reportData;

  // Gather statistics
  const allMatches = Array.from(sigmaMatches.values()).flat();
  const matchesBySeverity = {
    critical: allMatches.filter(m => m.rule.level === 'critical').length,
    high: allMatches.filter(m => m.rule.level === 'high').length,
    medium: allMatches.filter(m => m.rule.level === 'medium').length,
    low: allMatches.filter(m => m.rule.level === 'low').length,
    informational: allMatches.filter(m => m.rule.level === 'informational').length,
  };

  // Generate correlation chains if needed
  let chains: CorrelatedChain[] = [];
  if (options.includeCorrelationChains) {
    chains = correlateEvents(data.entries, sigmaMatches);
  }

  let html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>LUMEN Analysis Report - ${escapeHtml(filename)}</title>
  <style>
    :root {
      --bg-primary: #0f0f1a;
      --bg-secondary: #1a1a2e;
      --text-primary: #e4e4e7;
      --text-muted: #71717a;
      --accent-blue: #60a5fa;
      --accent-red: #ef4444;
      --accent-orange: #f97316;
      --accent-yellow: #eab308;
      --accent-green: #22c55e;
      --accent-purple: #a855f7;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: var(--bg-primary);
      color: var(--text-primary);
      line-height: 1.6;
      padding: 2rem;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    h1 { font-size: 2rem; color: var(--accent-blue); margin-bottom: 0.5rem; }
    h2 { font-size: 1.5rem; color: var(--text-primary); margin: 2rem 0 1rem; border-bottom: 2px solid var(--accent-blue); padding-bottom: 0.5rem; }
    h3 { font-size: 1.2rem; color: var(--accent-purple); margin: 1.5rem 0 0.75rem; }
    .meta { color: var(--text-muted); font-size: 0.9rem; margin-bottom: 2rem; }
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin: 1rem 0; }
    .stat-card { background: var(--bg-secondary); padding: 1rem; border-radius: 8px; text-align: center; }
    .stat-value { font-size: 2rem; font-weight: bold; color: var(--accent-blue); }
    .stat-label { font-size: 0.85rem; color: var(--text-muted); }
    .severity-critical { color: var(--accent-red); }
    .severity-high { color: var(--accent-orange); }
    .severity-medium { color: var(--accent-yellow); }
    .severity-low { color: var(--accent-green); }
    .severity-info { color: var(--accent-blue); }
    table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
    th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #2a2a3e; }
    th { background: var(--bg-secondary); color: var(--text-muted); font-weight: 600; }
    tr:hover { background: rgba(96, 165, 250, 0.05); }
    .badge { display: inline-block; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
    .badge-critical { background: rgba(239, 68, 68, 0.2); color: var(--accent-red); }
    .badge-high { background: rgba(249, 115, 22, 0.2); color: var(--accent-orange); }
    .badge-medium { background: rgba(234, 179, 8, 0.2); color: var(--accent-yellow); }
    .badge-low { background: rgba(34, 197, 94, 0.2); color: var(--accent-green); }
    .summary-box { background: var(--bg-secondary); padding: 1.5rem; border-radius: 8px; margin: 1rem 0; border-left: 4px solid var(--accent-blue); }
    .chain-card { background: var(--bg-secondary); padding: 1rem; border-radius: 8px; margin: 0.75rem 0; }
    .chain-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; }
    ul { margin-left: 1.5rem; }
    li { margin: 0.5rem 0; }
    code { background: var(--bg-secondary); padding: 0.2rem 0.4rem; border-radius: 4px; font-family: monospace; }
    .footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #2a2a3e; color: var(--text-muted); font-size: 0.85rem; text-align: center; }
    .detection-sample { margin: 1rem 0; padding: 1rem; background: var(--bg-secondary); border-left: 3px solid var(--accent-blue); border-radius: 4px; }
    .detection-sample-header { font-weight: 600; color: var(--accent-blue); margin-bottom: 0.5rem; }
    .field-match-table { width: 100%; margin-top: 0.5rem; font-size: 0.85rem; }
    .field-match-table th { background: rgba(96, 165, 250, 0.1); font-weight: 600; padding: 0.5rem; }
    .field-match-table td { padding: 0.5rem; word-break: break-all; }
    .field-modifier { display: inline-block; padding: 0.1rem 0.4rem; background: rgba(168, 85, 247, 0.2); color: var(--accent-purple); border-radius: 3px; font-size: 0.7rem; margin-left: 0.25rem; }
    @media print {
      body { background: white; color: black; }
      .stat-card, .summary-box, .chain-card { border: 1px solid #ddd; }
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>🔆 LUMEN Analysis Report</h1>
    <div class="meta">
      <strong>File:</strong> ${escapeHtml(filename)} |
      <strong>Platform:</strong> ${platform || 'N/A'} |
      <strong>Generated:</strong> ${generatedAt.toLocaleString()}
    </div>
`;

  // Executive Summary
  if (options.includeExecutiveSummary) {
    const riskLevel = matchesBySeverity.critical > 0 ? 'Critical' :
                      matchesBySeverity.high > 0 ? 'High' :
                      matchesBySeverity.medium > 0 ? 'Medium' : 'Low';

    html += `
    <h2>Executive Summary</h2>
    <div class="summary-box">
      <p><strong>Risk Assessment:</strong> <span class="severity-${riskLevel.toLowerCase()}">${riskLevel}</span></p>
      <p>Analysis of <strong>${data.entries.length.toLocaleString()}</strong> events identified <strong>${allMatches.length}</strong> SIGMA rule matches.</p>
      ${chains.length > 0 ? `<p>Correlation analysis identified <strong>${chains.length}</strong> related event chains.</p>` : ''}
    </div>

    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-value">${data.entries.length.toLocaleString()}</div>
        <div class="stat-label">Total Events</div>
      </div>
      <div class="stat-card">
        <div class="stat-value severity-critical">${matchesBySeverity.critical}</div>
        <div class="stat-label">Critical</div>
      </div>
      <div class="stat-card">
        <div class="stat-value severity-high">${matchesBySeverity.high}</div>
        <div class="stat-label">High</div>
      </div>
      <div class="stat-card">
        <div class="stat-value severity-medium">${matchesBySeverity.medium}</div>
        <div class="stat-label">Medium</div>
      </div>
      <div class="stat-card">
        <div class="stat-value severity-low">${matchesBySeverity.low}</div>
        <div class="stat-label">Low</div>
      </div>
    </div>
`;
  }

  // SIGMA Matches
  if (options.includeSigmaMatches && allMatches.length > 0) {
    html += `
    <h2>SIGMA Detections</h2>
    <p>Found ${allMatches.length} matches across ${sigmaMatches.size} unique rules.</p>
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Rule</th>
          <th>Description</th>
          <th>Event Count</th>
        </tr>
      </thead>
      <tbody>
`;

    // Group by rule
    const ruleGroups = new Map<string, SigmaRuleMatch[]>();
    allMatches.forEach(match => {
      const key = match.rule.id || match.rule.title;
      if (!ruleGroups.has(key)) ruleGroups.set(key, []);
      ruleGroups.get(key)!.push(match);
    });

    // Sort by severity
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
    const sortedRules = Array.from(ruleGroups.entries()).sort((a, b) => {
      const aLevel = a[1][0].rule.level || 'informational';
      const bLevel = b[1][0].rule.level || 'informational';
      return (severityOrder[aLevel as keyof typeof severityOrder] || 5) -
             (severityOrder[bLevel as keyof typeof severityOrder] || 5);
    });

    sortedRules.forEach(([, matches]) => {
      const rule = matches[0].rule;
      const level = rule.level || 'informational';
      html += `
        <tr>
          <td><span class="badge badge-${level}">${level.toUpperCase()}</span></td>
          <td>${escapeHtml(rule.title)}</td>
          <td>${escapeHtml(rule.description || '-')}</td>
          <td>${matches.length}</td>
        </tr>
`;
    });

    html += `
      </tbody>
    </table>
`;

    // Add detection samples section
    html += `
    <h3>Detection Samples</h3>
    <p>Showing up to 5 sample detections per rule</p>
`;

    sortedRules.forEach(([, matches]) => {
      const rule = matches[0].rule;
      const samples = matches.slice(0, 5); // First 5 samples

      html += `
    <div class="detection-sample">
      <div class="detection-sample-header">${escapeHtml(rule.title)}</div>
      <div style="font-size: 0.85rem; color: var(--text-muted);">
        Showing ${samples.length} of ${matches.length} detection(s)
      </div>
`;

      samples.forEach((match, idx) => {
        const eventData = extractEssentialEventData(match);
        const fieldMatches = extractFieldMatches(match);

        html += `
      <div style="margin-top: 1rem; padding: 0.75rem; background: rgba(0,0,0,0.2); border-radius: 4px;">
        <div style="font-weight: 600; margin-bottom: 0.5rem;">
          Sample ${idx + 1} - Event ${eventData.eventId || 'N/A'} - ${escapeHtml(eventData.computer || 'N/A')}
        </div>
        <div style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.5rem;">
          ${new Date(eventData.timestamp).toLocaleString()}
          ${eventData.sourceFile ? ` | File: ${escapeHtml(eventData.sourceFile)}` : ''}
        </div>
`;

        if (fieldMatches.length > 0) {
          html += `
        <table class="field-match-table">
          <thead>
            <tr>
              <th>Field</th>
              <th>Value</th>
              <th>Selection</th>
            </tr>
          </thead>
          <tbody>
`;

          fieldMatches.forEach(fm => {
            const valueStr = fm.value === '' ? '(empty)' : String(fm.value).substring(0, 150);
            const truncated = String(fm.value).length > 150 ? '...' : '';
            html += `
            <tr>
              <td>
                ${escapeHtml(fm.field)}
                ${fm.modifier ? `<span class="field-modifier">${escapeHtml(fm.modifier)}</span>` : ''}
              </td>
              <td><code>${escapeHtml(valueStr)}${truncated}</code></td>
              <td>${escapeHtml(fm.selection)}</td>
            </tr>
`;
          });

          html += `
          </tbody>
        </table>
`;
        } else {
          html += `<p style="font-size: 0.85rem; color: var(--text-muted);">No field match details available</p>`;
        }

        // Add raw event data
        html += `
        <details style="margin-top: 0.75rem;">
          <summary style="cursor: pointer; font-weight: 600; color: var(--accent-purple); font-size: 0.85rem;">View Raw Event Data</summary>
          <pre style="margin-top: 0.5rem; padding: 0.75rem; background: rgba(0,0,0,0.3); border-radius: 4px; overflow-x: auto; font-size: 0.75rem;"><code>${escapeHtml(JSON.stringify(match.event, null, 2))}</code></pre>
        </details>
`;

        html += `
      </div>
`;
      });

      html += `
    </div>
`;
    });
  }

  // Correlation Chains
  if (options.includeCorrelationChains && chains.length > 0) {
    html += `
    <h2>Correlated Event Chains</h2>
    <p>Identified ${chains.length} chains of related events.</p>
`;

    // Show top 20 chains
    chains.slice(0, 20).forEach((chain, i) => {
      html += `
    <div class="chain-card">
      <div class="chain-header">
        <span><strong>Chain ${i + 1}</strong> - <span class="badge badge-${chain.severity}">${chain.severity.toUpperCase()}</span></span>
        <span>Score: ${chain.score} | ${chain.events.length} events</span>
      </div>
      <p>${escapeHtml(chain.summary)}</p>
      <p><small>Duration: ${formatDuration(chain.duration)} | Hosts: ${Array.from(chain.involvedHosts).join(', ') || 'N/A'}</small></p>
    </div>
`;
    });

    if (chains.length > 20) {
      html += `<p><em>... and ${chains.length - 20} more chains</em></p>`;
    }
  }

  // Event Statistics
  if (options.includeEventStatistics) {
    html += `
    <h2>Event Statistics</h2>
`;

    // Event ID distribution
    const eventIdCounts = new Map<number, number>();
    data.entries.forEach(e => {
      const id = e.eventId || 0;
      eventIdCounts.set(id, (eventIdCounts.get(id) || 0) + 1);
    });

    const topEventIds = Array.from(eventIdCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 15);

    html += `
    <h3>Top Event IDs</h3>
    <table>
      <thead>
        <tr><th>Event ID</th><th>Count</th><th>Percentage</th></tr>
      </thead>
      <tbody>
`;
    topEventIds.forEach(([id, count]) => {
      const pct = ((count / data.entries.length) * 100).toFixed(1);
      html += `<tr><td>${id}</td><td>${count.toLocaleString()}</td><td>${pct}%</td></tr>`;
    });
    html += `</tbody></table>`;

    // Computer distribution
    const computerCounts = new Map<string, number>();
    data.entries.forEach(e => {
      const comp = e.computer || 'Unknown';
      computerCounts.set(comp, (computerCounts.get(comp) || 0) + 1);
    });

    html += `
    <h3>Computers</h3>
    <table>
      <thead>
        <tr><th>Computer</th><th>Events</th></tr>
      </thead>
      <tbody>
`;
    Array.from(computerCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .forEach(([comp, count]) => {
        html += `<tr><td>${escapeHtml(comp)}</td><td>${count.toLocaleString()}</td></tr>`;
      });
    html += `</tbody></table>`;
  }

  // Timeline
  if (options.includeTimeline && allMatches.length > 0) {
    html += `
    <h2>Detection Timeline</h2>
    <p>Chronological view of SIGMA detections.</p>
    <table>
      <thead>
        <tr><th>Time</th><th>Severity</th><th>Rule</th><th>Computer</th></tr>
      </thead>
      <tbody>
`;

    // Sort matches by time
    const sortedMatches = [...allMatches].sort((a, b) =>
      new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    ).slice(0, 100);

    sortedMatches.forEach(match => {
      const time = new Date(match.timestamp);
      const level = match.rule.level || 'informational';
      html += `
        <tr>
          <td>${time.toLocaleString()}</td>
          <td><span class="badge badge-${level}">${level.toUpperCase()}</span></td>
          <td>${escapeHtml(match.rule.title)}</td>
          <td>${escapeHtml(match.event?.computer || '-')}</td>
        </tr>
`;
    });

    if (allMatches.length > 100) {
      html += `<tr><td colspan="4"><em>... showing first 100 of ${allMatches.length} detections</em></td></tr>`;
    }

    html += `</tbody></table>`;
  }

  // Footer
  html += `
    <div class="footer">
      Generated by LUMEN - Log Analysis & SIGMA Detection Tool<br>
      All analysis performed locally in-browser. No data transmitted externally.
    </div>
  </div>
</body>
</html>`;

  return html;
}

// Generate Markdown report
function generateMarkdownReport(reportData: ReportData): string {
  const { filename, generatedAt, platform, data, sigmaMatches, options } = reportData;

  const allMatches = Array.from(sigmaMatches.values()).flat();
  const matchesBySeverity = {
    critical: allMatches.filter(m => m.rule.level === 'critical').length,
    high: allMatches.filter(m => m.rule.level === 'high').length,
    medium: allMatches.filter(m => m.rule.level === 'medium').length,
    low: allMatches.filter(m => m.rule.level === 'low').length,
  };

  let chains: CorrelatedChain[] = [];
  if (options.includeCorrelationChains) {
    chains = correlateEvents(data.entries, sigmaMatches);
  }

  let md = `# LUMEN Analysis Report

**File:** ${filename}
**Platform:** ${platform || 'N/A'}
**Generated:** ${generatedAt.toLocaleString()}

---

`;

  if (options.includeExecutiveSummary) {
    const riskLevel = matchesBySeverity.critical > 0 ? 'Critical' :
                      matchesBySeverity.high > 0 ? 'High' :
                      matchesBySeverity.medium > 0 ? 'Medium' : 'Low';

    md += `## Executive Summary

**Risk Level:** ${riskLevel}

| Metric | Value |
|--------|-------|
| Total Events | ${data.entries.length.toLocaleString()} |
| SIGMA Matches | ${allMatches.length} |
| Critical | ${matchesBySeverity.critical} |
| High | ${matchesBySeverity.high} |
| Medium | ${matchesBySeverity.medium} |
| Low | ${matchesBySeverity.low} |

`;
  }

  if (options.includeSigmaMatches && allMatches.length > 0) {
    md += `## SIGMA Detections

| Severity | Rule | Count |
|----------|------|-------|
`;

    const ruleGroups = new Map<string, SigmaRuleMatch[]>();
    allMatches.forEach(match => {
      const key = match.rule.title;
      if (!ruleGroups.has(key)) ruleGroups.set(key, []);
      ruleGroups.get(key)!.push(match);
    });

    Array.from(ruleGroups.entries())
      .sort((a, b) => b[1].length - a[1].length)
      .forEach(([title, matches]) => {
        const level = matches[0].rule.level || 'info';
        md += `| ${level.toUpperCase()} | ${title} | ${matches.length} |\n`;
      });

    md += '\n';

    // Add detection samples section
    md += `### Detection Samples\n\n`;
    md += 'Showing up to 3 sample detections per rule.\n\n';

    // Sort rule groups by severity for detection samples
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
    const sortedRules = Array.from(ruleGroups.entries()).sort((a, b) => {
      const aLevel = a[1][0].rule.level || 'informational';
      const bLevel = b[1][0].rule.level || 'informational';
      return (severityOrder[aLevel as keyof typeof severityOrder] || 5) -
             (severityOrder[bLevel as keyof typeof severityOrder] || 5);
    });

    sortedRules.forEach(([title, matches]) => {
      const samples = matches.slice(0, 3); // First 3 samples

      md += `#### ${title}\n\n`;
      md += `Showing ${samples.length} of ${matches.length} detection(s)\n\n`;

      samples.forEach((match, idx) => {
        const eventData = extractEssentialEventData(match);
        const fieldMatches = extractFieldMatches(match);

        md += `**Sample ${idx + 1}**\n\n`;
        md += `- **Event ID:** ${eventData.eventId || 'N/A'}\n`;
        md += `- **Computer:** ${eventData.computer || 'N/A'}\n`;
        md += `- **Timestamp:** ${new Date(eventData.timestamp).toLocaleString()}\n`;
        if (eventData.sourceFile) {
          md += `- **Source File:** ${eventData.sourceFile}\n`;
        }

        if (fieldMatches.length > 0) {
          md += `\n**Matched Fields:**\n\n`;
          md += `| Field | Value | Selection | Modifier |\n`;
          md += `|-------|-------|-----------|----------|\n`;

          fieldMatches.forEach(fm => {
            const valueStr = fm.value === '' ? '(empty)' : String(fm.value).substring(0, 100);
            const truncated = String(fm.value).length > 100 ? '...' : '';
            const escapedValue = valueStr.replace(/\|/g, '\\|').replace(/\n/g, ' ');
            md += `| ${fm.field} | \`${escapedValue}${truncated}\` | ${fm.selection} | ${fm.modifier || '-'} |\n`;
          });

          md += '\n';
        } else {
          md += `\n*No field match details available*\n\n`;
        }

        // Add raw event data
        md += `\n<details>\n<summary>View Raw Event Data</summary>\n\n\`\`\`json\n${JSON.stringify(match.event, null, 2)}\n\`\`\`\n\n</details>\n\n`;
      });

      md += '---\n\n';
    });
  }

  if (options.includeCorrelationChains && chains.length > 0) {
    md += `## Correlated Event Chains

Found **${chains.length}** chains of related events.

`;

    chains.slice(0, 10).forEach((chain, i) => {
      md += `### Chain ${i + 1} (${chain.severity.toUpperCase()})

- **Events:** ${chain.events.length}
- **Score:** ${chain.score}
- **Duration:** ${formatDuration(chain.duration)}
- **Summary:** ${chain.summary}

`;
    });
  }

  md += `---

*Generated by LUMEN - All analysis performed locally*
`;

  return md;
}

// Generate JSON report
function generateJSONReport(reportData: ReportData): string {
  const { filename, generatedAt, platform, data, sigmaMatches, options } = reportData;

  const allMatches = Array.from(sigmaMatches.values()).flat();

  let chains: CorrelatedChain[] = [];
  if (options.includeCorrelationChains) {
    chains = correlateEvents(data.entries, sigmaMatches);
  }

  const report: Record<string, unknown> = {
    meta: {
      filename,
      platform,
      generatedAt: generatedAt.toISOString(),
      generator: 'LUMEN Analysis Tool',
    },
    summary: {
      totalEvents: data.entries.length,
      totalMatches: allMatches.length,
      matchesBySeverity: {
        critical: allMatches.filter(m => m.rule.level === 'critical').length,
        high: allMatches.filter(m => m.rule.level === 'high').length,
        medium: allMatches.filter(m => m.rule.level === 'medium').length,
        low: allMatches.filter(m => m.rule.level === 'low').length,
      },
      correlationChains: chains.length,
    },
  };

  if (options.includeSigmaMatches) {
    report.sigmaMatches = allMatches.map(m => {
      const fieldMatches = extractFieldMatches(m);
      return {
        rule: {
          id: m.rule.id,
          title: m.rule.title,
          level: m.rule.level,
          description: m.rule.description,
        },
        event: extractEssentialEventData(m),
        rawEvent: m.event, // Include the complete original event data
        detectionDetails: {
          matchedFields: fieldMatches.map(fm => ({
            field: fm.field,
            value: fm.value,
            selection: fm.selection,
            modifier: fm.modifier,
            matchedPattern: fm.matchedPattern,
          })),
          totalFieldsMatched: fieldMatches.length,
        },
      };
    });
  }

  if (options.includeCorrelationChains) {
    report.correlationChains = chains.map(c => ({
      id: c.id,
      severity: c.severity,
      score: c.score,
      eventCount: c.events.length,
      duration: c.duration,
      summary: c.summary,
      hosts: Array.from(c.involvedHosts),
      sigmaMatchCount: c.sigmaMatches.length,
    }));
  }

  if (options.includeEventStatistics) {
    const eventIdCounts: Record<number, number> = {};
    data.entries.forEach(e => {
      const id = e.eventId || 0;
      eventIdCounts[id] = (eventIdCounts[id] || 0) + 1;
    });
    report.eventStatistics = { eventIdDistribution: eventIdCounts };
  }

  return JSON.stringify(report, null, 2);
}

// Helper functions
function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  if (ms < 3600000) return `${(ms / 60000).toFixed(1)}m`;
  return `${(ms / 3600000).toFixed(1)}h`;
}

/**
 * Extract field match details from a SIGMA rule match
 * @param match - The SIGMA rule match object
 * @returns Array of extracted field matches with relevant details
 */
function extractFieldMatches(match: SigmaRuleMatch): ExtractedFieldMatch[] {
  const results: ExtractedFieldMatch[] = [];

  if (!match.selectionMatches || match.selectionMatches.length === 0) {
    return results;
  }

  for (const selMatch of match.selectionMatches) {
    if (!selMatch.fieldMatches) continue;

    const isFilterSelection = selMatch.selection.toLowerCase().startsWith('filter');

    for (const fm of selMatch.fieldMatches) {
      // Skip undefined/null values unless it's a filter selection
      if (!isFilterSelection && (fm.value === undefined || fm.value === null)) {
        continue;
      }

      // Truncate very long values (>500 chars) for export
      let value = fm.value;
      if (typeof value === 'string' && value.length > 500) {
        value = value.substring(0, 500) + '...';
      } else if (Array.isArray(value)) {
        value = value.join(', ');
        if (typeof value === 'string' && value.length > 500) {
          value = value.substring(0, 500) + '...';
        }
      } else if (typeof value === 'object' && value !== null) {
        value = JSON.stringify(value);
        if (value.length > 500) {
          value = value.substring(0, 500) + '...';
        }
      }

      results.push({
        field: fm.field,
        value: value,
        selection: selMatch.selection,
        modifier: fm.modifier,
        matchedPattern: fm.matchedPattern,
      });
    }
  }

  return results;
}

/**
 * Extract essential event data from a SIGMA rule match
 * @param match - The SIGMA rule match object
 * @returns Essential event metadata
 */
function extractEssentialEventData(match: SigmaRuleMatch): EssentialEventData {
  const event = match.event as any;

  return {
    eventId: event?.EventID || event?.eventId,
    computer: event?.Computer || event?.computer,
    timestamp: match.timestamp instanceof Date
      ? match.timestamp.toISOString()
      : new Date(match.timestamp).toISOString(),
    source: event?.Source || event?.source || event?.Provider_Name,
    sourceFile: event?.sourceFile,
    level: event?.Level || event?.level,
  };
}

// Download report as file
export function downloadReport(content: string, filename: string, format: 'html' | 'markdown' | 'json'): void {
  const mimeTypes = {
    html: 'text/html',
    markdown: 'text/markdown',
    json: 'application/json',
  };

  const extensions = {
    html: '.html',
    markdown: '.md',
    json: '.json',
  };

  const blob = new Blob([content], { type: mimeTypes[format] });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename.replace(/\.[^.]+$/, '') + '_report' + extensions[format];
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
