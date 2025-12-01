/**
 * Event Correlation Engine
 * Links related events into attack chains based on process relationships,
 * network connections, file operations, and temporal proximity.
 */

import { LogEntry } from '../types';
import { SigmaRuleMatch } from './sigma/types';

// Relationship types between events
export type RelationshipType =
  | 'process_spawn'      // Parent spawned child process
  | 'network_connection' // Process made network connection
  | 'file_operation'     // Process created/modified file
  | 'registry_operation' // Process modified registry
  | 'temporal'           // Events within time window
  | 'same_process';      // Same process, different events

export interface EventRelationship {
  sourceIndex: number;
  targetIndex: number;
  type: RelationshipType;
  field: string;
  confidence: number; // 0-1, how confident we are in this relationship
}

export interface CorrelatedChain {
  id: string;
  events: LogEntry[];
  eventIndices: number[];
  relationships: EventRelationship[];
  startTime: Date;
  endTime: Date;
  duration: number; // milliseconds
  involvedProcesses: Set<string>;
  involvedHosts: Set<string>;
  sigmaMatches: SigmaRuleMatch[];
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  score: number; // Threat score based on various factors
  summary: string;
}

// Sysmon / Security Event IDs
const EVENT_TYPES = {
  PROCESS_CREATE: 1,
  SECURITY_PROCESS_CREATE: 4688,
  FILE_CREATE_TIME: 2,
  NETWORK_CONNECT: 3,
  SYSMON_STATE: 4,
  PROCESS_TERMINATE: 5,
  DRIVER_LOAD: 6,
  IMAGE_LOAD: 7,
  CREATE_REMOTE_THREAD: 8,
  RAW_ACCESS_READ: 9,
  PROCESS_ACCESS: 10,
  FILE_CREATE: 11,
  REGISTRY_EVENT: 12,
  REGISTRY_SET: 13,
  REGISTRY_RENAME: 14,
  FILE_CREATE_STREAM: 15,
  SYSMON_CONFIG: 16,
  PIPE_CREATED: 17,
  PIPE_CONNECTED: 18,
  WMI_FILTER: 19,
  WMI_CONSUMER: 20,
  WMI_BINDING: 21,
  DNS_QUERY: 22,
  FILE_DELETE: 23,
  CLIPBOARD: 24,
  PROCESS_TAMPERING: 25,
  FILE_DELETE_LOGGED: 26,
};

// Extract field from structured eventData (preferred) or rawLine
function extractField(entry: LogEntry, fieldName: string): string | null {
  if (entry.eventData && entry.eventData[fieldName]) {
    return entry.eventData[fieldName];
  }

  const rawLine = entry.rawLine || '';

  // Try XML format: <Data Name="FieldName">value</Data>
  const xmlMatch = rawLine.match(new RegExp(`<Data[^>]*Name=["']${fieldName}["'][^>]*>([^<]*)</Data>`, 'i'));
  if (xmlMatch) return xmlMatch[1];

  // Try key: value format
  const kvMatch = rawLine.match(new RegExp(`${fieldName}:\\s*([^\\s,;]+)`, 'i'));
  if (kvMatch) return kvMatch[1];

  return null;
}

// Extract process GUID from event
function getProcessGuid(entry: LogEntry): string | null {
  return extractField(entry, 'ProcessGuid') ||
         extractField(entry, 'SourceProcessGuid') ||
         extractField(entry, 'NewProcessId') || // Security 4688
         extractField(entry, 'ProcessId');      // Security 4688 parent
}

// Extract parent process GUID
function getParentProcessGuid(entry: LogEntry): string | null {
  return extractField(entry, 'ParentProcessGuid') ||
         extractField(entry, 'ParentProcessId') ||
         extractField(entry, 'ProcessId'); // Security 4688 parent
}

// Extract target process GUID (for process access events)
function getTargetProcessGuid(entry: LogEntry): string | null {
  return extractField(entry, 'TargetProcessGuid');
}

// Extract process image name
function getProcessImage(entry: LogEntry): string | null {
  const image = extractField(entry, 'Image') ||
                extractField(entry, 'SourceImage') ||
                extractField(entry, 'NewProcessName'); // Security 4688
  if (!image) return null;
  // Get just the filename
  const parts = image.split(/[\\\/]/);
  return parts[parts.length - 1].toLowerCase();
}

// Build indices for fast lookup
interface EventIndices {
  byProcessGuid: Map<string, number[]>;
  byParentGuid: Map<string, number[]>;
  byTargetGuid: Map<string, number[]>;
  byEventId: Map<number, number[]>;
  byComputer: Map<string, number[]>;
}

function buildIndices(entries: LogEntry[]): EventIndices {
  const indices: EventIndices = {
    byProcessGuid: new Map(),
    byParentGuid: new Map(),
    byTargetGuid: new Map(),
    byEventId: new Map(),
    byComputer: new Map(),
  };

  entries.forEach((entry, idx) => {
    // Index by process GUID
    const procGuid = getProcessGuid(entry);
    if (procGuid) {
      const existing = indices.byProcessGuid.get(procGuid) || [];
      existing.push(idx);
      indices.byProcessGuid.set(procGuid, existing);
    }

    // Index by parent GUID
    const parentGuid = getParentProcessGuid(entry);
    if (parentGuid) {
      const existing = indices.byParentGuid.get(parentGuid) || [];
      existing.push(idx);
      indices.byParentGuid.set(parentGuid, existing);
    }

    // Index by target GUID
    const targetGuid = getTargetProcessGuid(entry);
    if (targetGuid) {
      const existing = indices.byTargetGuid.get(targetGuid) || [];
      existing.push(idx);
      indices.byTargetGuid.set(targetGuid, existing);
    }

    // Index by event ID
    if (entry.eventId) {
      const existing = indices.byEventId.get(entry.eventId) || [];
      existing.push(idx);
      indices.byEventId.set(entry.eventId, existing);
    }

    // Index by computer
    if (entry.computer) {
      const existing = indices.byComputer.get(entry.computer) || [];
      existing.push(idx);
      indices.byComputer.set(entry.computer, existing);
    }
  });

  return indices;
}

// Union-Find data structure for building chains
class UnionFind {
  parent: number[];
  rank: number[];

  constructor(size: number) {
    this.parent = Array.from({ length: size }, (_, i) => i);
    this.rank = new Array(size).fill(0);
  }

  find(x: number): number {
    if (this.parent[x] !== x) {
      this.parent[x] = this.find(this.parent[x]);
    }
    return this.parent[x];
  }

  union(x: number, y: number): void {
    const rootX = this.find(x);
    const rootY = this.find(y);

    if (rootX !== rootY) {
      if (this.rank[rootX] < this.rank[rootY]) {
        this.parent[rootX] = rootY;
      } else if (this.rank[rootX] > this.rank[rootY]) {
        this.parent[rootY] = rootX;
      } else {
        this.parent[rootY] = rootX;
        this.rank[rootX]++;
      }
    }
  }

  connected(x: number, y: number): boolean {
    return this.find(x) === this.find(y);
  }
}

// Find relationships between events
function findRelationships(
  entries: LogEntry[],
  indices: EventIndices
): EventRelationship[] {
  const relationships: EventRelationship[] = [];

  entries.forEach((entry, idx) => {
    const procGuid = getProcessGuid(entry);
    const parentGuid = getParentProcessGuid(entry);
    const targetGuid = getTargetProcessGuid(entry);

    // Process spawn relationships (EID 1)
    if ((entry.eventId === EVENT_TYPES.PROCESS_CREATE || entry.eventId === EVENT_TYPES.SECURITY_PROCESS_CREATE) && parentGuid) {
      // Find parent process events
      const parentEvents = indices.byProcessGuid.get(parentGuid) || [];
      for (const parentIdx of parentEvents) {
        if (parentIdx !== idx) {
          relationships.push({
            sourceIndex: parentIdx,
            targetIndex: idx,
            type: 'process_spawn',
            field: 'ParentProcessGuid',
            confidence: 1.0,
          });
        }
      }
    }

    // Same process relationships (different events for same process)
    if (procGuid) {
      const sameProcessEvents = indices.byProcessGuid.get(procGuid) || [];
      for (const otherIdx of sameProcessEvents) {
        if (otherIdx < idx) { // Only link to earlier events to avoid duplicates
          relationships.push({
            sourceIndex: otherIdx,
            targetIndex: idx,
            type: 'same_process',
            field: 'ProcessGuid',
            confidence: 1.0,
          });
        }
      }
    }

    // Process access relationships (EID 10)
    if (entry.eventId === EVENT_TYPES.PROCESS_ACCESS && targetGuid) {
      const targetEvents = indices.byProcessGuid.get(targetGuid) || [];
      for (const targetIdx of targetEvents) {
        if (targetIdx !== idx) {
          relationships.push({
            sourceIndex: idx,
            targetIndex: targetIdx,
            type: 'process_spawn', // Treating as related
            field: 'TargetProcessGuid',
            confidence: 0.8,
          });
        }
      }
    }

    // Network connection from process (EID 3)
    if (entry.eventId === EVENT_TYPES.NETWORK_CONNECT && procGuid) {
      const processEvents = indices.byProcessGuid.get(procGuid) || [];
      for (const procIdx of processEvents) {
        if (procIdx !== idx && (entries[procIdx].eventId === EVENT_TYPES.PROCESS_CREATE || entries[procIdx].eventId === EVENT_TYPES.SECURITY_PROCESS_CREATE)) {
          relationships.push({
            sourceIndex: procIdx,
            targetIndex: idx,
            type: 'network_connection',
            field: 'ProcessGuid',
            confidence: 1.0,
          });
        }
      }
    }

    // File operations (EID 11, 23, 26)
    if ([EVENT_TYPES.FILE_CREATE, EVENT_TYPES.FILE_DELETE, EVENT_TYPES.FILE_DELETE_LOGGED].includes(entry.eventId || 0) && procGuid) {
      const processEvents = indices.byProcessGuid.get(procGuid) || [];
      for (const procIdx of processEvents) {
        if (procIdx !== idx && (entries[procIdx].eventId === EVENT_TYPES.PROCESS_CREATE || entries[procIdx].eventId === EVENT_TYPES.SECURITY_PROCESS_CREATE)) {
          relationships.push({
            sourceIndex: procIdx,
            targetIndex: idx,
            type: 'file_operation',
            field: 'ProcessGuid',
            confidence: 1.0,
          });
        }
      }
    }

    // Registry operations (EID 12, 13, 14)
    if ([EVENT_TYPES.REGISTRY_EVENT, EVENT_TYPES.REGISTRY_SET, EVENT_TYPES.REGISTRY_RENAME].includes(entry.eventId || 0) && procGuid) {
      const processEvents = indices.byProcessGuid.get(procGuid) || [];
      for (const procIdx of processEvents) {
        if (procIdx !== idx && (entries[procIdx].eventId === EVENT_TYPES.PROCESS_CREATE || entries[procIdx].eventId === EVENT_TYPES.SECURITY_PROCESS_CREATE)) {
          relationships.push({
            sourceIndex: procIdx,
            targetIndex: idx,
            type: 'registry_operation',
            field: 'ProcessGuid',
            confidence: 1.0,
          });
        }
      }
    }
  });

  return relationships;
}

// Calculate severity based on chain characteristics
function calculateSeverity(
  chain: LogEntry[],
  sigmaMatches: SigmaRuleMatch[]
): { severity: CorrelatedChain['severity']; score: number } {
  let score = 0;

  // Base score from SIGMA matches
  for (const match of sigmaMatches) {
    switch (match.rule.level) {
      case 'critical': score += 100; break;
      case 'high': score += 50; break;
      case 'medium': score += 20; break;
      case 'low': score += 5; break;
    }
  }

  // Bonus for chain length (more events = potentially more significant)
  score += Math.min(chain.length * 2, 30);

  // Check for suspicious patterns
  const eventIds = chain.map(e => e.eventId).filter(Boolean);

  // Process creation followed by network = potential C2
  if (eventIds.some(id => id === EVENT_TYPES.PROCESS_CREATE || id === EVENT_TYPES.SECURITY_PROCESS_CREATE) &&
      eventIds.includes(EVENT_TYPES.NETWORK_CONNECT)) {
    score += 15;
  }

  // Remote thread creation = injection
  if (eventIds.includes(EVENT_TYPES.CREATE_REMOTE_THREAD)) {
    score += 30;
  }

  // Process access = potential credential theft
  if (eventIds.includes(EVENT_TYPES.PROCESS_ACCESS)) {
    score += 20;
  }

  // Determine severity from score
  let severity: CorrelatedChain['severity'];
  if (score >= 100) severity = 'critical';
  else if (score >= 50) severity = 'high';
  else if (score >= 20) severity = 'medium';
  else if (score >= 5) severity = 'low';
  else severity = 'info';

  return { severity, score };
}

// Generate summary for a chain
function generateChainSummary(chain: LogEntry[], _relationships: EventRelationship[]): string {
  const processes = new Set<string>();
  const eventTypes = new Set<number>();

  for (const event of chain) {
    const image = getProcessImage(event);
    if (image) processes.add(image);
    if (event.eventId) eventTypes.add(event.eventId);
  }

  const parts: string[] = [];

  if (processes.size > 0) {
    parts.push(`Processes: ${Array.from(processes).slice(0, 3).join(', ')}${processes.size > 3 ? '...' : ''}`);
  }

  const actions: string[] = [];
  if (eventTypes.has(EVENT_TYPES.PROCESS_CREATE) || eventTypes.has(EVENT_TYPES.SECURITY_PROCESS_CREATE)) actions.push('spawned');
  if (eventTypes.has(EVENT_TYPES.NETWORK_CONNECT)) actions.push('connected');
  if (eventTypes.has(EVENT_TYPES.FILE_CREATE)) actions.push('created files');
  if (eventTypes.has(EVENT_TYPES.REGISTRY_SET)) actions.push('modified registry');
  if (eventTypes.has(EVENT_TYPES.CREATE_REMOTE_THREAD)) actions.push('injected');

  if (actions.length > 0) {
    parts.push(`Actions: ${actions.join(', ')}`);
  }

  return parts.join(' | ') || `${chain.length} related events`;
}

// Main correlation function
export function correlateEvents(
  entries: LogEntry[],
  sigmaMatches: Map<string, SigmaRuleMatch[]>,
  onProgress?: (processed: number, total: number) => void
): CorrelatedChain[] {
  if (entries.length === 0) return [];

  // Cap at 50K events - ONLY events with SIGMA hits + context (±1 event)
  const MAX_EVENTS_TO_CORRELATE = 50000;
  let entriesToProcess = entries;

  // Get events with SIGMA matches
  const eventsWithMatches = new Set<LogEntry>();
  for (const matches of sigmaMatches.values()) {
    for (const match of matches) {
      if (match.event) {
        eventsWithMatches.add(match.event);
      }
    }
  }

  if (eventsWithMatches.size === 0) {
    console.warn('No SIGMA matches found. Event correlation requires SIGMA detections.');
    return [];
  }

  // Add ±1 context events around each SIGMA match
  const eventsWithContext = new Set<LogEntry>();

  // Create an index map for fast lookups
  const eventIndexMap = new Map<LogEntry, number>();
  entries.forEach((event, idx) => {
    eventIndexMap.set(event, idx);
  });

  // For each SIGMA match, add the event and ±1 neighbors
  for (const matchedEvent of eventsWithMatches) {
    const idx = eventIndexMap.get(matchedEvent);
    if (idx !== undefined) {
      // Add the matched event
      eventsWithContext.add(matchedEvent);

      // Add previous event if exists
      if (idx > 0) {
        eventsWithContext.add(entries[idx - 1]);
      }

      // Add next event if exists
      if (idx < entries.length - 1) {
        eventsWithContext.add(entries[idx + 1]);
      }
    }
  }

  // If we have more events than the limit, prioritize SIGMA matches
  if (eventsWithContext.size > MAX_EVENTS_TO_CORRELATE) {
    console.warn(`${eventsWithContext.size} events (SIGMA + context). Limiting to ${MAX_EVENTS_TO_CORRELATE}.`);

    // Ensure all SIGMA matches are included, then add context events
    const finalEvents = new Set<LogEntry>(eventsWithMatches);

    // Add context events until we hit the limit
    for (const event of eventsWithContext) {
      if (finalEvents.size >= MAX_EVENTS_TO_CORRELATE) break;
      finalEvents.add(event);
    }

    entriesToProcess = Array.from(finalEvents).sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
  } else {
    entriesToProcess = Array.from(eventsWithContext).sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
  }

  console.log(`Correlating ${entriesToProcess.length} events (${eventsWithMatches.size} SIGMA matches + context)`);

  // Build indices for fast lookup
  if (onProgress) onProgress(1, 5);
  const indices = buildIndices(entriesToProcess);

  // Find all relationships
  if (onProgress) onProgress(2, 5);
  const relationships = findRelationships(entriesToProcess, indices);

  // Use Union-Find to group related events
  if (onProgress) onProgress(3, 5);
  const uf = new UnionFind(entriesToProcess.length);
  for (const rel of relationships) {
    uf.union(rel.sourceIndex, rel.targetIndex);
  }

  // Group events by their chain root
  if (onProgress) onProgress(4, 5);
  const chainGroups = new Map<number, number[]>();
  for (let i = 0; i < entriesToProcess.length; i++) {
    const root = uf.find(i);
    const group = chainGroups.get(root) || [];
    group.push(i);
    chainGroups.set(root, group);
  }

  // Build chain objects
  const chains: CorrelatedChain[] = [];
  let chainId = 0;

  for (const [, eventIndices] of chainGroups) {
    // Skip single-event chains (no relationships)
    if (eventIndices.length < 2) continue;

    // Sort by timestamp
    eventIndices.sort((a, b) =>
      entriesToProcess[a].timestamp.getTime() - entriesToProcess[b].timestamp.getTime()
    );

    const chainEvents = eventIndices.map(i => entriesToProcess[i]);
    const chainRelationships = relationships.filter(
      r => eventIndices.includes(r.sourceIndex) && eventIndices.includes(r.targetIndex)
    );

    // Collect SIGMA matches for this chain
    // Build a set of matched events for deduplication
    const matchedEventSet = new Set<SigmaRuleMatch>();

    for (const idx of eventIndices) {
      const event = entriesToProcess[idx];

      // Check all matches to find ones that correspond to this event
      for (const [, matches] of sigmaMatches) {
        for (const match of matches) {
          // Skip if already matched
          if (matchedEventSet.has(match)) continue;

          // Only use strict matching (matches final filter logic)
          // Direct object reference match (most reliable)
          if (match.event === event) {
            matchedEventSet.add(match);
            continue;
          }

          // Match by rawLine content (unique per event)
          if (match.event?.rawLine && event.rawLine && match.event.rawLine === event.rawLine) {
            matchedEventSet.add(match);
          }
        }
      }
    }

    const chainSigmaMatches = Array.from(matchedEventSet);

    // Filter matches to ensure they belong to this chain
    // Don't deduplicate by rule ID - keep all matches for proper event-to-rule mapping
    // Use strict matching: only exact object reference or exact rawLine match
    const uniqueMatches = chainSigmaMatches.filter(match =>
      chainEvents.some(event => {
        const matchEvent = match.event;
        if (!matchEvent) return false;

        // Exact object reference match (most reliable)
        if (event === matchEvent) return true;

        // Exact rawLine match (second most reliable)
        if (event.rawLine && matchEvent.rawLine && event.rawLine === matchEvent.rawLine) return true;

        // No timestamp-based matching - it's too unreliable
        // Different events can share the same eventId and have close timestamps
        return false;
      })
    );

    // Calculate severity
    const { severity, score } = calculateSeverity(chainEvents, uniqueMatches);

    // Collect involved processes and hosts
    const involvedProcesses = new Set<string>();
    const involvedHosts = new Set<string>();
    for (const event of chainEvents) {
      const image = getProcessImage(event);
      if (image) involvedProcesses.add(image);
      if (event.computer) involvedHosts.add(event.computer);
    }

    const startTime = chainEvents[0].timestamp;
    const endTime = chainEvents[chainEvents.length - 1].timestamp;

    chains.push({
      id: `chain-${chainId++}`,
      events: chainEvents,
      eventIndices,
      relationships: chainRelationships,
      startTime,
      endTime,
      duration: endTime.getTime() - startTime.getTime(),
      involvedProcesses,
      involvedHosts,
      sigmaMatches: uniqueMatches,
      severity,
      score,
      summary: generateChainSummary(chainEvents, chainRelationships),
    });
  }

  // Sort chains by score (most severe first)
  chains.sort((a, b) => b.score - a.score);

  if (onProgress) onProgress(5, 5);

  return chains;
}

// Get statistics about correlations
export function getCorrelationStats(chains: CorrelatedChain[]) {
  return {
    totalChains: chains.length,
    bySeverity: {
      critical: chains.filter(c => c.severity === 'critical').length,
      high: chains.filter(c => c.severity === 'high').length,
      medium: chains.filter(c => c.severity === 'medium').length,
      low: chains.filter(c => c.severity === 'low').length,
      info: chains.filter(c => c.severity === 'info').length,
    },
    avgChainLength: chains.length > 0
      ? chains.reduce((sum, c) => sum + c.events.length, 0) / chains.length
      : 0,
    longestChain: chains.length > 0
      ? Math.max(...chains.map(c => c.events.length))
      : 0,
    totalEventsCorrelated: chains.reduce((sum, c) => sum + c.events.length, 0),
    chainsWithSigma: chains.filter(c => c.sigmaMatches.length > 0).length,
  };
}
