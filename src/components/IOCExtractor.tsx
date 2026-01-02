import { useMemo, useState, useCallback } from 'react';
import { LogEntry } from '../types';
import { lookupIOC, VTResponse, getAPIKey, saveAPIKey, clearAPIKey } from '../lib/virusTotal';
import { SigmaRuleMatch } from '../lib/sigma/types';
import { IOCPivotView } from './IOCPivotView';
import './IOCExtractor.css';

interface IOCExtractorProps {
  entries: LogEntry[];
  onBack: () => void;
  sigmaMatches?: Map<string, SigmaRuleMatch[]>;
}

// IOC types
type IOCType = 'ip' | 'domain' | 'hash' | 'filepath' | 'url' | 'email' | 'registry' | 'base64';

interface ExtractedIOC {
  type: IOCType;
  value: string;
  count: number;
  sources: string[]; // Which fields it was found in
}

// Patterns that look like version strings (to filter false positive IPs)
const VERSION_CONTEXT_PATTERNS = [
  /version[:\s]+\d+\.\d+\.\d+\.\d+/gi,
  /v\d+\.\d+\.\d+\.\d+/gi,
  /\d+\.\d+\.\d+\.\d+[\s-]*(build|release|beta|alpha|rc|patch)/gi,
  /(build|release|beta|alpha|rc|patch|rev)[\s-]*\d+\.\d+\.\d+\.\d+/gi,
  /\.NET Framework \d+\.\d+\.\d+\.\d+/gi,
  /Windows \d+\.\d+\.\d+\.\d+/gi,
  /assembly[^,]*\d+\.\d+\.\d+\.\d+/gi,
];

// Check if an IP-like string appears in a version context within the source text
function isVersionString(potentialIP: string, sourceText: string): boolean {
  // Check if this IP appears in a version-like context
  for (const pattern of VERSION_CONTEXT_PATTERNS) {
    const matches = sourceText.match(pattern);
    if (matches && matches.some(m => m.includes(potentialIP))) {
      return true;
    }
  }

  // Also filter IPs that end with .0 in the last two octets (common version patterns)
  // e.g., 6.0.0.0, 4.0.0.0, 2.0.0.0 are almost always versions
  const parts = potentialIP.split('.').map(Number);
  if (parts[2] === 0 && parts[3] === 0 && parts[0] < 20) {
    return true;
  }

  return false;
}

// Regex patterns for IOC extraction
const IOC_PATTERNS: Record<IOCType, RegExp> = {
  ip: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
  domain: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|edu|gov|mil|io|co|info|biz|xyz|online|site|tech|cloud|app|dev|me|tv|cc|ru|cn|de|uk|fr|jp|br|au|in|nl|es|it|pl|ca|se|ch|be|at|dk|no|fi|ie|nz|sg|hk|kr|tw|mx|ar|za|ua|cz|hu|ro|gr|pt|il|ae|sa|pk|bd|vn|th|ph|my|id|tr|eg)\b/gi,
  hash: /\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b/g,
  // Only match Windows paths (C:\...) - Unix paths have too many false positives with command args
  filepath: /[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n\s]+\\)*[^\\/:*?"<>|\r\n\s]+/g,
  url: /https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_+.~#?&/=]*)/gi,
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  // Registry keys - matches common Windows registry hives and paths
  registry: /\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s"'<>|]+/gi,
  // Base64 - matches strings that are likely Base64 encoded (min 20 chars, proper padding)
  base64: /\b(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4}){5,}\b/g
};

// Validate file path to filter out command-line arguments
function isValidFilePath(path: string): boolean {
  // Must be at least 5 chars (e.g., C:\a)
  if (path.length < 5) return false;
  // Must start with drive letter
  if (!/^[A-Za-z]:\\/.test(path)) return false;
  // Must not contain typical command-line argument patterns
  if (/^[A-Za-z]:\\[A-Z]+\s/.test(path)) return false;
  // Must have a file extension or be a directory path ending in \
  if (!/\.\w{1,10}$/.test(path) && !path.endsWith('\\')) return false;
  return true;
}

// Validate Base64 string - check if it decodes to something meaningful
function isLikelyBase64(str: string): boolean {
  // Must be at least 20 chars to avoid false positives
  if (str.length < 20) return false;

  // Check for proper Base64 structure
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(str)) return false;

  // Length must be valid for Base64 (multiple of 4)
  if (str.length % 4 !== 0) return false;

  try {
    const decoded = atob(str);
    // Check if decoded content has mostly printable ASCII or common binary patterns
    let printableCount = 0;
    let controlCount = 0;
    for (let i = 0; i < decoded.length && i < 100; i++) {
      const code = decoded.charCodeAt(i);
      if (code >= 32 && code <= 126) printableCount++;
      else if (code < 32 && code !== 9 && code !== 10 && code !== 13) controlCount++;
    }
    // If more than 60% printable or has PowerShell/command indicators, likely real
    const sampleLength = Math.min(decoded.length, 100);
    const printableRatio = printableCount / sampleLength;

    // Look for command-like patterns in decoded content
    const hasCommandPatterns = /powershell|cmd|invoke|iex|downloadstring|webclient|system\.|exec|eval/i.test(decoded);

    return printableRatio > 0.6 || hasCommandPatterns;
  } catch {
    return false;
  }
}

// IOC type labels and icons
const IOC_INFO: Record<IOCType, { label: string; icon: string; description: string }> = {
  ip: { label: 'IP Addresses', icon: '🌐', description: 'IPv4 addresses found in logs' },
  domain: { label: 'Domains', icon: '🔗', description: 'Domain names and hostnames' },
  hash: { label: 'File Hashes', icon: '🔑', description: 'MD5, SHA1, and SHA256 hashes' },
  filepath: { label: 'File Paths', icon: '📁', description: 'Windows and Unix file paths' },
  url: { label: 'URLs', icon: '🔗', description: 'Full URLs with protocols' },
  email: { label: 'Email Addresses', icon: '📧', description: 'Email addresses' },
  registry: { label: 'Registry Keys', icon: '🗝️', description: 'Windows registry key paths' },
  base64: { label: 'Base64 Strings', icon: '🔐', description: 'Encoded strings (potentially malicious commands)' }
};

// Filter out common false positives
const FALSE_POSITIVES: Record<IOCType, string[]> = {
  ip: ['0.0.0.0', '127.0.0.1', '255.255.255.255', '224.0.0.1'],
  domain: ['localhost', 'example.com', 'test.com'],
  hash: [],
  filepath: [],
  url: [],
  email: [],
  registry: [],
  base64: []
};

// Check if an IP address is in a reserved/non-routable range
function isReservedIP(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(p => isNaN(p))) return false;

  const [a, b, c] = parts;

  // 0.0.0.0/8 - "This" network
  if (a === 0) return true;

  // 10.0.0.0/8 - Private (RFC 1918)
  if (a === 10) return true;

  // 100.64.0.0/10 - Carrier-grade NAT (RFC 6598)
  if (a === 100 && b >= 64 && b <= 127) return true;

  // 127.0.0.0/8 - Loopback
  if (a === 127) return true;

  // 169.254.0.0/16 - Link-local
  if (a === 169 && b === 254) return true;

  // 172.16.0.0/12 - Private (RFC 1918)
  if (a === 172 && b >= 16 && b <= 31) return true;

  // 192.0.0.0/24 - IETF Protocol Assignments
  if (a === 192 && b === 0 && c === 0) return true;

  // 192.0.2.0/24 - TEST-NET-1 (documentation)
  if (a === 192 && b === 0 && c === 2) return true;

  // 192.88.99.0/24 - 6to4 relay anycast
  if (a === 192 && b === 88 && c === 99) return true;

  // 192.168.0.0/16 - Private (RFC 1918)
  if (a === 192 && b === 168) return true;

  // 198.18.0.0/15 - Benchmarking
  if (a === 198 && (b === 18 || b === 19)) return true;

  // 198.51.100.0/24 - TEST-NET-2 (documentation)
  if (a === 198 && b === 51 && c === 100) return true;

  // 203.0.113.0/24 - TEST-NET-3 (documentation)
  if (a === 203 && b === 0 && c === 113) return true;

  // 224.0.0.0/4 - Multicast
  if (a >= 224 && a <= 239) return true;

  // 240.0.0.0/4 - Reserved for future use
  if (a >= 240 && a <= 255) return true;

  return false;
}

// Common benign paths to optionally filter
const BENIGN_PATHS = [
  'C:\\Windows\\System32',
  'C:\\Windows\\SysWOW64',
  'C:\\Program Files',
  'C:\\Program Files (x86)',
  '/usr/bin',
  '/usr/lib',
  '/bin',
  '/sbin'
];

export default function IOCExtractor({ entries, onBack, sigmaMatches }: IOCExtractorProps) {
  const [selectedTypes, setSelectedTypes] = useState<Set<IOCType>>(
    new Set(['ip', 'domain', 'hash', 'filepath', 'url', 'email', 'registry', 'base64'])
  );
  const [searchQuery, setSearchQuery] = useState('');
  const [showBenignPaths, setShowBenignPaths] = useState(false);
  const [copiedIOC, setCopiedIOC] = useState<string | null>(null);

  // VirusTotal integration state
  const [vtApiKey, setVtApiKey] = useState<string>(getAPIKey() || '');
  const [showVtConfig, setShowVtConfig] = useState(false);
  const [vtResults, setVtResults] = useState<Map<string, VTResponse>>(new Map());
  const [vtLookupQueue, setVtLookupQueue] = useState<string[]>([]);
  const [isLookingUp, setIsLookingUp] = useState(false);
  const hasVtKey = vtApiKey.trim().length > 0;

  // Pivot functionality state
  const [pivotIOC, setPivotIOC] = useState<ExtractedIOC | null>(null);

  // Limit processing to first 50K events to avoid crashing on very large files
  const limitedEntries = useMemo(() => entries.slice(0, 50000), [entries]);

  // Extract all IOCs from log entries
  const extractedIOCs = useMemo(() => {
    const iocMap = new Map<string, ExtractedIOC>();

    for (const entry of limitedEntries) {
      // Fields to search for IOCs
      const searchFields = [
        { name: 'rawLine', value: entry.rawLine },
        { name: 'message', value: entry.message },
        { name: 'path', value: entry.path },
        { name: 'ip', value: entry.ip },
        { name: 'computer', value: entry.computer },
        { name: 'userAgent', value: entry.userAgent }
      ];

      for (const { name, value } of searchFields) {
        if (!value) continue;

        // Extract each IOC type
        for (const [type, pattern] of Object.entries(IOC_PATTERNS) as [IOCType, RegExp][]) {
          const matches = value.match(pattern);
          if (!matches) continue;

          for (const match of matches) {
            // Skip false positives
            if (FALSE_POSITIVES[type].includes(match.toLowerCase())) continue;

            // Skip reserved/non-routable IP addresses
            if (type === 'ip' && isReservedIP(match)) continue;

            // Skip version strings that look like IPs (e.g., 6.0.0.0, Version 4.0.0.0)
            if (type === 'ip' && isVersionString(match, value)) continue;

            // Validate file paths to filter out command-line fragments
            if (type === 'filepath' && !isValidFilePath(match)) continue;

            // Skip benign paths if filter is enabled
            if (type === 'filepath' && !showBenignPaths) {
              const isbenign = BENIGN_PATHS.some(bp =>
                match.toLowerCase().startsWith(bp.toLowerCase())
              );
              if (isbenign) continue;
            }

            // Validate Base64 strings to reduce false positives
            if (type === 'base64' && !isLikelyBase64(match)) continue;

            const key = `${type}:${match.toLowerCase()}`;
            const existing = iocMap.get(key);

            if (existing) {
              existing.count++;
              if (!existing.sources.includes(name)) {
                existing.sources.push(name);
              }
            } else {
              iocMap.set(key, {
                type,
                value: match,
                count: 1,
                sources: [name]
              });
            }
          }
        }
      }
    }

    return Array.from(iocMap.values());
  }, [entries, showBenignPaths]);

  // Filter and sort IOCs
  const filteredIOCs = useMemo(() => {
    let result = extractedIOCs.filter(ioc => selectedTypes.has(ioc.type));

    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      result = result.filter(ioc => ioc.value.toLowerCase().includes(query));
    }

    // Sort by count descending, then alphabetically
    return result.sort((a, b) => b.count - a.count || a.value.localeCompare(b.value));
  }, [extractedIOCs, selectedTypes, searchQuery]);

  // Group IOCs by type for display
  const groupedIOCs = useMemo(() => {
    const groups: Record<IOCType, ExtractedIOC[]> = {
      ip: [],
      domain: [],
      hash: [],
      filepath: [],
      url: [],
      email: [],
      registry: [],
      base64: []
    };

    for (const ioc of filteredIOCs) {
      groups[ioc.type].push(ioc);
    }

    return groups;
  }, [filteredIOCs]);

  // Stats
  const stats = useMemo(() => {
    const byType: Record<IOCType, number> = {
      ip: 0, domain: 0, hash: 0, filepath: 0, url: 0, email: 0, registry: 0, base64: 0
    };

    for (const ioc of extractedIOCs) {
      byType[ioc.type]++;
    }

    return {
      total: extractedIOCs.length,
      filtered: filteredIOCs.length,
      byType
    };
  }, [extractedIOCs, filteredIOCs]);

  // VirusTotal API key handlers
  const handleSaveApiKey = useCallback(() => {
    if (vtApiKey.trim()) {
      saveAPIKey(vtApiKey.trim());
      setShowVtConfig(false);
    }
  }, [vtApiKey]);

  const handleClearApiKey = useCallback(() => {
    clearAPIKey();
    setVtApiKey('');
    setVtResults(new Map());
  }, []);

  // Lookup single IOC on VirusTotal
  const lookupSingleIOC = useCallback(async (type: IOCType, value: string) => {
    const apiKey = getAPIKey();
    if (!apiKey || !hasVtKey) {
      alert('VirusTotal API key is required. Please configure your API key first.');
      setShowVtConfig(true);
      return;
    }

    if (!['ip', 'domain', 'hash', 'url'].includes(type)) return;

    const key = `${type}:${value}`;
    setVtResults(prev => new Map(prev).set(key, { positives: 0, total: 0, loading: true }));

    const result = await lookupIOC(type as 'ip' | 'domain' | 'hash' | 'url', value, apiKey);
    setVtResults(prev => new Map(prev).set(key, result));
  }, [hasVtKey]);

  // Batch lookup all IOCs on VirusTotal
  const lookupAllIOCs = useCallback(async () => {
    const apiKey = getAPIKey();
    if (!apiKey || !hasVtKey) {
      alert('VirusTotal API key is required. Please configure your API key first.');
      setShowVtConfig(true);
      return;
    }

    const supportedIOCs = extractedIOCs.filter(
      ioc => ['ip', 'domain', 'hash', 'url'].includes(ioc.type)
    );

    if (supportedIOCs.length === 0) {
      alert('No supported IOCs found for VirusTotal lookup. Only IPs, domains, hashes, and URLs are supported.');
      return;
    }

    setIsLookingUp(true);
    setVtLookupQueue(supportedIOCs.map(ioc => `${ioc.type}:${ioc.value}`));

    for (const ioc of supportedIOCs) {
      const key = `${ioc.type}:${ioc.value}`;
      if (vtResults.has(key) && !vtResults.get(key)?.error) {
        setVtLookupQueue(prev => prev.filter(k => k !== key));
        continue;
      }

      setVtResults(prev => new Map(prev).set(key, { positives: 0, total: 0, loading: true }));
      const result = await lookupIOC(
        ioc.type as 'ip' | 'domain' | 'hash' | 'url',
        ioc.value,
        apiKey
      );
      setVtResults(prev => new Map(prev).set(key, result));
      setVtLookupQueue(prev => prev.filter(k => k !== key));
    }

    setIsLookingUp(false);
  }, [extractedIOCs, vtResults, hasVtKey]);

  // Toggle IOC type filter
  const toggleType = useCallback((type: IOCType) => {
    setSelectedTypes(prev => {
      const next = new Set(prev);
      if (next.has(type)) {
        next.delete(type);
      } else {
        next.add(type);
      }
      return next;
    });
  }, []);

  // Copy single IOC
  const copyIOC = useCallback((value: string) => {
    navigator.clipboard.writeText(value);
    setCopiedIOC(value);
    setTimeout(() => setCopiedIOC(null), 2000);
  }, []);

  // Copy all IOCs of a type
  const copyAllOfType = useCallback((type: IOCType) => {
    const values = groupedIOCs[type].map(ioc => ioc.value).join('\n');
    navigator.clipboard.writeText(values);
    setCopiedIOC(`all-${type}`);
    setTimeout(() => setCopiedIOC(null), 2000);
  }, [groupedIOCs]);

  // Export all filtered IOCs
  const exportIOCs = useCallback(() => {
    const output: Record<string, string[]> = {};

    for (const [type, iocs] of Object.entries(groupedIOCs)) {
      if (iocs.length > 0) {
        output[type] = iocs.map(ioc => ioc.value);
      }
    }

    const json = JSON.stringify(output, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'extracted_iocs.json';
    a.click();
    URL.revokeObjectURL(url);
  }, [groupedIOCs]);

  // Export as CSV
  const exportCSV = useCallback(() => {
    const rows = ['Type,Value,Count,Sources'];

    for (const ioc of filteredIOCs) {
      rows.push(`${ioc.type},"${ioc.value}",${ioc.count},"${ioc.sources.join('; ')}"`);
    }

    const csv = rows.join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'extracted_iocs.csv';
    a.click();
    URL.revokeObjectURL(url);
  }, [filteredIOCs]);

  return (
    <div className="ioc-extractor">
      <header className="ioc-header">
        <div>
          <h1>🎯 IOC Extractor</h1>
          <p className="ioc-subtitle">
            Extract Indicators of Compromise from {entries.length.toLocaleString()} log entries
          </p>
        </div>
        <button className="back-button" onClick={onBack}>
          ← Back to Selection
        </button>
      </header>

      {/* Stats Overview */}
      <div className="ioc-stats">
        <div className="stat-card total">
          <span className="stat-number">{stats.total}</span>
          <span className="stat-label">Total IOCs Found</span>
        </div>
        {(Object.entries(stats.byType) as [IOCType, number][]).map(([type, count]) => (
          <div
            key={type}
            className={`stat-card ${type} ${selectedTypes.has(type) ? 'active' : 'inactive'}`}
            onClick={() => toggleType(type)}
          >
            <span className="stat-icon">{IOC_INFO[type].icon}</span>
            <span className="stat-number">{count}</span>
            <span className="stat-label">{IOC_INFO[type].label}</span>
          </div>
        ))}
      </div>

      {/* Controls */}
      <div className="ioc-controls">
        <div className="search-box">
          <input
            type="text"
            placeholder="Search IOCs..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="search-input"
          />
        </div>

        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={showBenignPaths}
            onChange={(e) => setShowBenignPaths(e.target.checked)}
          />
          Show benign system paths
        </label>

        <div className="export-buttons">
          <button className="export-btn" onClick={exportIOCs}>
            📥 Export JSON
          </button>
          <button className="export-btn" onClick={exportCSV}>
            📊 Export CSV
          </button>
        </div>

        <div className="vt-controls">
          <button
            className={`vt-btn ${isLookingUp ? 'loading' : ''} ${!hasVtKey ? 'disabled' : ''}`}
            onClick={lookupAllIOCs}
            disabled={isLookingUp || !hasVtKey}
            title={hasVtKey ? "Lookup IPs, domains, hashes, and URLs on VirusTotal" : "VirusTotal API key required - Click to configure"}
          >
            {hasVtKey ? (isLookingUp ? `Looking up (${vtLookupQueue.length})...` : 'VT Lookup All') : '🔒 API Key Required'}
          </button>
          <button
            className="vt-config-btn"
            onClick={() => setShowVtConfig(!showVtConfig)}
            title={hasVtKey ? "API key configured - Click to update" : "Configure VirusTotal API key"}
          >
            {hasVtKey ? '✓ ⚙' : '⚙'}
          </button>
        </div>
      </div>

      {/* VirusTotal API Key Configuration */}
      {showVtConfig && (
        <div className="vt-config-panel">
          <h4>VirusTotal API Configuration</h4>
          <p className="vt-config-info">
            A VirusTotal API key is <strong>required</strong> to perform IOC lookups.
            {' '}Get your free API key at <a href="https://www.virustotal.com/gui/my-apikey" target="_blank" rel="noopener noreferrer">virustotal.com/gui/my-apikey</a>
          </p>
          <div className="vt-config-form">
            <input
              type="password"
              placeholder="Enter VirusTotal API key..."
              value={vtApiKey}
              onChange={(e) => setVtApiKey(e.target.value)}
              className="vt-api-input"
            />
            <button className="vt-save-btn" onClick={handleSaveApiKey} disabled={!vtApiKey.trim()}>
              Save
            </button>
            {getAPIKey() && (
              <button className="vt-clear-btn" onClick={handleClearApiKey}>
                Clear
              </button>
            )}
          </div>
          <p className="vt-privacy-note">
            🔒 Your API key is stored locally in your browser and never sent anywhere except VirusTotal.
          </p>
        </div>
      )}

      {/* IOC Lists */}
      <div className="ioc-lists">
        {(Object.entries(groupedIOCs) as [IOCType, ExtractedIOC[]][]).map(([type, iocs]) => {
          if (!selectedTypes.has(type) || iocs.length === 0) return null;

          return (
            <div key={type} className={`ioc-section ${type}`}>
              <div className="section-header">
                <h3>
                  {IOC_INFO[type].icon} {IOC_INFO[type].label}
                  <span className="section-count">({iocs.length})</span>
                </h3>
                <button
                  className={`copy-all-btn ${copiedIOC === `all-${type}` ? 'copied' : ''}`}
                  onClick={() => copyAllOfType(type)}
                >
                  {copiedIOC === `all-${type}` ? '✓ Copied!' : '📋 Copy All'}
                </button>
              </div>
              <p className="section-description">{IOC_INFO[type].description}</p>
              <div className="ioc-list">
                {iocs.slice(0, 100).map((ioc, idx) => {
                  const vtKey = `${ioc.type}:${ioc.value}`;
                  const vtResult = vtResults.get(vtKey);
                  const isVtSupported = ['ip', 'domain', 'hash', 'url'].includes(ioc.type);

                  return (
                    <div key={idx} className="ioc-item">
                      <span className="ioc-value" title={ioc.value}>
                        {ioc.value.length > 80 ? ioc.value.substring(0, 80) + '...' : ioc.value}
                      </span>
                      <span className="ioc-count" title={`Found ${ioc.count} times`}>
                        ×{ioc.count}
                      </span>

                      {/* VirusTotal result indicator */}
                      {isVtSupported && vtResult && (
                        <span
                          className={`vt-result ${vtResult.loading ? 'loading' : vtResult.error ? 'error' : vtResult.positives > 0 ? 'detected' : 'clean'}`}
                          title={vtResult.loading ? 'Looking up...' : vtResult.error || `${vtResult.positives}/${vtResult.total} detections`}
                        >
                          {vtResult.loading ? '⏳' : vtResult.error ? '⚠️' : vtResult.positives > 0 ? `🚨 ${vtResult.positives}/${vtResult.total}` : '✅'}
                        </span>
                      )}

                      {/* VT lookup button for supported types */}
                      {isVtSupported && !vtResult && (
                        <button
                          className={`vt-lookup-btn ${!hasVtKey ? 'disabled' : ''}`}
                          onClick={() => lookupSingleIOC(ioc.type, ioc.value)}
                          disabled={!hasVtKey}
                          title={hasVtKey ? "Lookup on VirusTotal" : "VirusTotal API key required"}
                        >
                          {hasVtKey ? 'VT' : '🔒'}
                        </button>
                      )}

                      {/* VT permalink */}
                      {vtResult?.permalink && (
                        <a
                          href={vtResult.permalink}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="vt-link"
                          title="View on VirusTotal"
                        >
                          ↗
                        </a>
                      )}

                      {/* Pivot button */}
                      <button
                        className="pivot-btn"
                        onClick={() => setPivotIOC(ioc)}
                        title={`Search all events for ${ioc.value}`}
                      >
                        Pivot
                      </button>

                      <button
                        className={`copy-btn ${copiedIOC === ioc.value ? 'copied' : ''}`}
                        onClick={() => copyIOC(ioc.value)}
                        title="Copy to clipboard"
                      >
                        {copiedIOC === ioc.value ? '✓' : '📋'}
                      </button>
                    </div>
                  );
                })}
                {iocs.length > 100 && (
                  <div className="more-iocs">
                    +{iocs.length - 100} more {IOC_INFO[type].label.toLowerCase()}
                  </div>
                )}
              </div>
            </div>
          );
        })}

        {filteredIOCs.length === 0 && (
          <div className="no-iocs">
            <span className="no-iocs-icon">🔍</span>
            <h3>No IOCs Found</h3>
            <p>
              {searchQuery
                ? 'No IOCs match your search query. Try a different search term.'
                : 'No indicators of compromise were found in the log entries.'}
            </p>
          </div>
        )}
      </div>

      <div className="privacy-note">
        🔒 All extraction is performed locally in your browser. No data is sent anywhere.
      </div>

      {/* IOC Pivot Modal */}
      {pivotIOC && (
        <IOCPivotView
          ioc={pivotIOC.value}
          type={pivotIOC.type}
          entries={entries}
          sigmaMatches={sigmaMatches || new Map()}
          onClose={() => setPivotIOC(null)}
        />
      )}
    </div>
  );
}
