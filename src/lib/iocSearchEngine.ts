/**
 * IOC Search Engine
 * Provides search functionality for finding IOCs across all parsed events
 */

import { LogEntry } from '../types';
import { SigmaRuleMatch } from './sigma/types';

// IOC types supported by the search engine
export type IOCType = 'ip' | 'domain' | 'hash' | 'filepath' | 'url' | 'email' | 'registry' | 'base64';

/**
 * Result of searching for an IOC across all events
 */
export interface IOCSearchResult {
  ioc: string;
  type: IOCType;
  totalMatches: number;
  eventsByFile: Map<string, IOCEventMatch[]>;
  eventsByType: Map<string, IOCEventMatch[]>;  // Grouped by EventID-Channel
  events: IOCEventMatch[];
  timelineData: IOCTimelinePoint[];
  firstSeen: Date | null;
  lastSeen: Date | null;
}

/**
 * An event that matched an IOC search
 */
export interface IOCEventMatch {
  event: LogEntry;
  eventIndex: number;
  matchedFields: string[];
  hasSigmaMatch: boolean;
  sigmaRules?: string[];
  sigmaMatches?: SigmaRuleMatch[];  // Full match objects for displaying matched fields
}

/**
 * Timeline data point for visualizing IOC appearances over time
 */
export interface IOCTimelinePoint {
  timestamp: Date;
  count: number;
  hour: string;  // "YYYY-MM-DD HH:00"
}

/**
 * Fields to search for IOCs in each event
 */
const SEARCH_FIELDS = [
  'rawLine',
  'message',
  'CommandLine',
  'ParentCommandLine',
  'TargetFilename',
  'SourceIp',
  'DestinationIp',
  'DestinationHostname',
  'QueryName',
  'QueryResults',
  'TargetObject',
  'Details',
  'Image',
  'ParentImage',
  'Hashes',
  'User',
  'SourceHostname',
  'DestinationPort',
  'SourcePort',
];

/**
 * Build a lookup of events that have SIGMA matches for O(1) access
 * Returns both rule IDs and full match objects
 */
function buildSigmaEventLookup(
  sigmaMatches: Map<string, SigmaRuleMatch[]>
): Map<LogEntry, { ruleIds: string[]; matches: SigmaRuleMatch[] }> {
  const eventLookup = new Map<LogEntry, { ruleIds: string[]; matches: SigmaRuleMatch[] }>();

  for (const [ruleId, matches] of sigmaMatches) {
    for (const match of matches) {
      if (match.event) {
        const entry = match.event as LogEntry;
        const existing = eventLookup.get(entry) || { ruleIds: [], matches: [] };
        existing.ruleIds.push(ruleId);
        existing.matches.push(match);
        eventLookup.set(entry, existing);
      }
    }
  }

  return eventLookup;
}

/**
 * Check if a string value contains the IOC
 */
function valueContainsIOC(value: string, ioc: string, type: IOCType): boolean {
  if (!value) return false;

  const lowerValue = value.toLowerCase();
  const lowerIOC = ioc.toLowerCase();

  switch (type) {
    case 'ip':
      // For IPs, look for exact match with word boundaries
      // Handle both bare IPs and IPs with ports (192.168.1.1:443)
      const ipPattern = new RegExp(`\\b${escapeRegex(ioc)}(?::\\d+)?\\b`);
      return ipPattern.test(value);

    case 'domain':
      // Domain can appear as subdomain or exact match
      return lowerValue.includes(lowerIOC);

    case 'hash':
      // Hashes should be case-insensitive exact matches
      return lowerValue.includes(lowerIOC);

    case 'filepath':
      // File paths - case-insensitive on Windows
      return lowerValue.includes(lowerIOC);

    case 'url':
      // URLs - look for the full URL or significant portions
      return lowerValue.includes(lowerIOC);

    case 'email':
      // Email addresses - case-insensitive
      return lowerValue.includes(lowerIOC);

    case 'registry':
      // Registry keys - case-insensitive
      return lowerValue.includes(lowerIOC);

    case 'base64':
      // Base64 - exact match
      return value.includes(ioc);

    default:
      return lowerValue.includes(lowerIOC);
  }
}

/**
 * Escape special regex characters in a string
 */
function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Find which fields in an event contain the IOC
 */
export function findIOCInEvent(
  event: LogEntry,
  ioc: string,
  type: IOCType
): string[] {
  const matchedFields: string[] = [];

  // Check rawLine
  if (event.rawLine && valueContainsIOC(event.rawLine, ioc, type)) {
    matchedFields.push('rawLine');
  }

  // Check message
  if (event.message && valueContainsIOC(event.message, ioc, type)) {
    matchedFields.push('message');
  }

  // Check eventData fields
  if (event.eventData) {
    for (const field of SEARCH_FIELDS) {
      if (field === 'rawLine' || field === 'message') continue;

      const value = event.eventData[field];
      if (value && typeof value === 'string' && valueContainsIOC(value, ioc, type)) {
        matchedFields.push(field);
      }
    }

    // Also check any field in eventData that wasn't in our list
    for (const [field, value] of Object.entries(event.eventData)) {
      if (SEARCH_FIELDS.includes(field)) continue;
      if (typeof value === 'string' && valueContainsIOC(value, ioc, type)) {
        matchedFields.push(field);
      }
    }
  }

  return matchedFields;
}

/**
 * Build timeline data by grouping events by hour
 */
export function buildTimelineData(events: IOCEventMatch[]): IOCTimelinePoint[] {
  const hourCounts = new Map<string, { timestamp: Date; count: number }>();

  for (const eventMatch of events) {
    const timestamp = eventMatch.event.timestamp;
    if (!timestamp) continue;

    const date = new Date(timestamp);
    const hourKey = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')} ${String(date.getHours()).padStart(2, '0')}:00`;

    const existing = hourCounts.get(hourKey);
    if (existing) {
      existing.count++;
    } else {
      hourCounts.set(hourKey, { timestamp: date, count: 1 });
    }
  }

  // Convert to array and sort by timestamp
  const timeline: IOCTimelinePoint[] = [];
  for (const [hour, data] of hourCounts) {
    timeline.push({
      timestamp: data.timestamp,
      count: data.count,
      hour,
    });
  }

  timeline.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

  return timeline;
}

/**
 * Search for an IOC across all events
 */
export function searchIOCInEvents(
  ioc: string,
  type: IOCType,
  entries: LogEntry[],
  sigmaMatches: Map<string, SigmaRuleMatch[]>
): IOCSearchResult {
  const events: IOCEventMatch[] = [];
  const eventsByFile = new Map<string, IOCEventMatch[]>();
  const eventsByType = new Map<string, IOCEventMatch[]>();

  // Build SIGMA lookup for O(1) access
  const sigmaEventLookup = buildSigmaEventLookup(sigmaMatches);

  let firstSeen: Date | null = null;
  let lastSeen: Date | null = null;

  // Search through all entries
  for (let idx = 0; idx < entries.length; idx++) {
    const entry = entries[idx];
    const matchedFields = findIOCInEvent(entry, ioc, type);

    if (matchedFields.length === 0) continue;

    // Get SIGMA info
    const sigmaInfo = sigmaEventLookup.get(entry);

    const eventMatch: IOCEventMatch = {
      event: entry,
      eventIndex: idx,
      matchedFields,
      hasSigmaMatch: !!sigmaInfo,
      sigmaRules: sigmaInfo?.ruleIds,
      sigmaMatches: sigmaInfo?.matches,
    };

    events.push(eventMatch);

    // Track first/last seen
    if (entry.timestamp) {
      const timestamp = new Date(entry.timestamp);
      if (!firstSeen || timestamp < firstSeen) {
        firstSeen = timestamp;
      }
      if (!lastSeen || timestamp > lastSeen) {
        lastSeen = timestamp;
      }
    }

    // Group by file
    const file = entry.sourceFile || 'Unknown';
    if (!eventsByFile.has(file)) {
      eventsByFile.set(file, []);
    }
    eventsByFile.get(file)!.push(eventMatch);

    // Group by event type (EventID - Source/Channel)
    const eventId = entry.eventId || 'Unknown';
    const source = entry.source || entry.eventData?.Channel || 'Unknown';
    const eventTypeKey = `Event ${eventId} - ${source}`;
    if (!eventsByType.has(eventTypeKey)) {
      eventsByType.set(eventTypeKey, []);
    }
    eventsByType.get(eventTypeKey)!.push(eventMatch);
  }

  return {
    ioc,
    type,
    totalMatches: events.length,
    eventsByFile,
    eventsByType,
    events,
    timelineData: buildTimelineData(events),
    firstSeen,
    lastSeen,
  };
}

/**
 * Get a display name for an IOC type
 */
export function getIOCTypeLabel(type: IOCType): string {
  const labels: Record<IOCType, string> = {
    ip: 'IP Address',
    domain: 'Domain',
    hash: 'File Hash',
    filepath: 'File Path',
    url: 'URL',
    email: 'Email',
    registry: 'Registry Key',
    base64: 'Base64 String',
  };
  return labels[type] || type;
}

/**
 * Get an icon for an IOC type
 */
export function getIOCTypeIcon(type: IOCType): string {
  const icons: Record<IOCType, string> = {
    ip: '🌐',
    domain: '🔗',
    hash: '🔑',
    filepath: '📁',
    url: '🔗',
    email: '📧',
    registry: '🗝️',
    base64: '🔐',
  };
  return icons[type] || '📌';
}
