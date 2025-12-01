/**
 * Optimized SIGMA Rule Matcher
 *
 * Performance optimizations:
 * 1. EventID indexing - events grouped by EventID for O(1) lookup
 * 2. Rule grouping by EventID - only run relevant rules against relevant events
 * 3. Logsource pre-filtering - skip rules that don't match event source
 * 4. Chunked async processing - keeps UI responsive
 */

import { CompiledSigmaRule, SigmaRuleMatch, SigmaLogSource } from '../types';
import { matchRule, preIndexEventFields } from './matcher';
import { LogEntry } from '../../../types';

/**
 * Category to EventID mapping based on SIGMA taxonomy (sigma-appendix-taxonomy.md)
 * This maps logsource categories to their expected Sysmon/Windows EventIDs
 *
 * Reference: https://github.com/SigmaHQ/sigma/wiki/Taxonomy-Appendix
 */
const CATEGORY_TO_EVENTID: Record<string, number[]> = {
  // Sysmon categories (Microsoft-Windows-Sysmon/Operational)
  'process_creation': [1, 4688],       // Sysmon EID 1, Security EID 4688
  'file_change': [2],                   // Sysmon EID 2
  'network_connection': [3],            // Sysmon EID 3
  'sysmon_status': [4, 16],             // Sysmon EID 4, 16
  'process_termination': [5],           // Sysmon EID 5
  'driver_load': [6],                   // Sysmon EID 6
  'image_load': [7],                    // Sysmon EID 7
  'create_remote_thread': [8],          // Sysmon EID 8
  'raw_access_thread': [9],             // Sysmon EID 9
  'process_access': [10],               // Sysmon EID 10
  'file_event': [11],                   // Sysmon EID 11
  'registry_event': [12, 13, 14],       // Sysmon EID 12, 13, 14
  'registry_add': [12],                 // Sysmon EID 12
  'registry_delete': [12],              // Sysmon EID 12
  'registry_set': [13],                 // Sysmon EID 13
  'registry_rename': [14],              // Sysmon EID 14
  'create_stream_hash': [15],           // Sysmon EID 15
  'pipe_created': [17, 18],             // Sysmon EID 17, 18
  'wmi_event': [19, 20, 21],            // Sysmon EID 19, 20, 21
  'dns_query': [22],                    // Sysmon EID 22
  'file_delete': [23],                  // Sysmon EID 23
  'clipboard_capture': [24],            // Sysmon EID 24
  'process_tampering': [25],            // Sysmon EID 25
  'file_delete_detected': [26],         // Sysmon EID 26
  'file_block_executable': [27],        // Sysmon EID 27
  'file_block_shredding': [28],         // Sysmon EID 28
  'file_executable_detected': [29],     // Sysmon EID 29
  'sysmon_error': [255],                // Sysmon EID 255

  // PowerShell categories (Windows PowerShell / Microsoft-Windows-PowerShell/Operational)
  'ps_classic_start': [400],            // Windows PowerShell EID 400
  'ps_classic_provider_start': [600],   // Windows PowerShell EID 600
  'ps_classic_script': [800],           // Windows PowerShell EID 800
  'ps_module': [4103],                  // PowerShell/Operational EID 4103
  'ps_script': [4104],                  // PowerShell/Operational EID 4104
};

/**
 * Service to common EventIDs (for rules that filter by service + EventID)
 * Based on SIGMA taxonomy (sigma-appendix-taxonomy.md)
 *
 * Note: These are used as fallback when a rule has no category but has a service.
 * Services without known EventID patterns will cause rules to run against all events.
 */
const SERVICE_EVENTID_HINTS: Record<string, number[]> = {
  // Sysmon (Microsoft-Windows-Sysmon/Operational)
  'sysmon': [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 255],

  // Security (Security channel) - common security EventIDs
  'security': [
    // Logon events
    4624, 4625, 4634, 4647, 4648, 4649, 4672, 4675,
    // Process events
    4688, 4689, 4696,
    // Scheduled task events
    4698, 4699, 4700, 4701, 4702,
    // Privilege events
    4703, 4704, 4705, 4719,
    // Account management
    4720, 4722, 4723, 4724, 4725, 4726, 4727, 4728, 4729, 4730,
    4731, 4732, 4733, 4734, 4735, 4737, 4738, 4739, 4740, 4741, 4742, 4743,
    // Group management
    4754, 4755, 4756, 4757, 4758, 4764, 4767,
    // Kerberos events
    4768, 4769, 4770, 4771, 4772, 4773, 4774, 4775, 4776,
    // Session events
    4778, 4779,
    // User/group enumeration
    4798, 4799,
    // Directory service events
    5136, 5137, 5138, 5139, 5141,
    // File share events
    5140, 5142, 5143, 5144, 5145,
    // Firewall events
    5152, 5153, 5154, 5155, 5156, 5157, 5158, 5159,
    // Other security events
    4657, 4663, 4670, 4673, 4674
  ],

  // System (System channel)
  'system': [
    104,   // Event log cleared
    1074,  // System shutdown
    6005, 6006, 6008, 6009, 6013, // System events
    7000, 7001, 7009, 7011,       // Service Control Manager
    7022, 7023, 7024, 7026, 7031, 7032, 7034,
    7036, 7040, 7045,             // Service state changes
    10016  // DCOM error
  ],

  // PowerShell (Microsoft-Windows-PowerShell/Operational)
  'powershell': [4103, 4104, 4105, 4106],

  // PowerShell Classic (Windows PowerShell)
  'powershell-classic': [400, 403, 500, 501, 600, 800],

  // Application (Application channel) - generic, no specific EventIDs
  'application': [],

  // WMI Activity (Microsoft-Windows-WMI-Activity/Operational)
  'wmi': [5857, 5858, 5859, 5860, 5861],

  // Task Scheduler (Microsoft-Windows-TaskScheduler/Operational)
  'taskscheduler': [106, 129, 140, 141, 142, 200, 201],

  // Windows Defender (Microsoft-Windows-Windows Defender/Operational)
  'windefend': [1006, 1007, 1008, 1009, 1010, 1011, 1013, 1116, 1117, 1118, 1119, 5001, 5007, 5010, 5012],

  // AppLocker
  'applocker': [8002, 8003, 8004, 8005, 8006, 8007],

  // DNS Server
  'dns-server': [150, 770, 541],

  // BITS Client (Microsoft-Windows-Bits-Client/Operational)
  'bits-client': [3, 4, 59, 60, 61],

  // Code Integrity (Microsoft-Windows-CodeIntegrity/Operational)
  'codeintegrity-operational': [3001, 3002, 3003, 3004, 3033],

  // Firewall (Microsoft-Windows-Windows Firewall With Advanced Security/Firewall)
  'firewall-as': [2003, 2004, 2005, 2006],

  // PrintService
  'printservice-admin': [808, 842, 843],
  'printservice-operational': [307, 800, 801, 805, 812, 823, 831, 842, 843, 845, 846, 847, 848, 849],

  // Terminal Services
  'terminalservices-localsessionmanager': [21, 22, 23, 24, 25, 39, 40],

  // NTLM (Microsoft-Windows-NTLM/Operational)
  'ntlm': [8001, 8002, 8003, 8004],

  // LSA (Microsoft-Windows-LSA/Operational)
  'lsa-server': [300, 301, 302, 303, 304, 305],

  // Shell Core (Microsoft-Windows-Shell-Core/Operational)
  'shell-core': [9707, 9708, 28115],

  // Driver Framework (Microsoft-Windows-DriverFrameworks-UserMode/Operational)
  'driver-framework': [2003, 2004, 2010, 2100, 2101, 2102, 2103, 2105, 2106],

  // OpenSSH
  'openssh': [4],

  // SMB Client
  'smbclient-security': [31001]
};

/**
 * Extract EventID requirements from a compiled rule
 * Returns null if rule applies to all EventIDs (no specific requirement)
 */
export function extractRuleEventIDs(rule: CompiledSigmaRule): number[] | null {
  const eventIds = new Set<number>();

  // 1. Check logsource category for implicit EventID
  const category = rule.rule.logsource?.category;

  if (category && CATEGORY_TO_EVENTID[category]) {
    for (const id of CATEGORY_TO_EVENTID[category]) {
      eventIds.add(id);
    }
  }

  // 2. Check logsource service for hints
  const service = rule.rule.logsource?.service;
  if (service && SERVICE_EVENTID_HINTS[service] && eventIds.size === 0) {
    // Only use service hints if no category EventIDs found
    for (const id of SERVICE_EVENTID_HINTS[service]) {
      eventIds.add(id);
    }
  }

  // 3. Check selection conditions for explicit EventID field
  for (const [, selection] of rule.selections) {
    for (const condition of selection.conditions) {
      if (condition.field === 'EventID' || condition.field === 'eventId') {
        for (const value of condition.values) {
          if (typeof value === 'number') {
            eventIds.add(value);
          } else if (typeof value === 'string') {
            const parsed = parseInt(value, 10);
            if (!isNaN(parsed)) {
              eventIds.add(parsed);
            }
          }
        }
      }
    }
  }

  // Return null if no specific EventIDs (rule applies to all events)
  return eventIds.size > 0 ? Array.from(eventIds) : null;
}

/**
 * Check if a rule's logsource is compatible with Windows EVTX logs
 * Returns false for rules targeting other products (Linux, macOS, etc.)
 */
export function isWindowsCompatibleRule(logsource: SigmaLogSource): boolean {
  // If no logsource requirements, match all
  if (!logsource.product && !logsource.service && !logsource.category) {
    return true;
  }

  // Explicitly Windows-targeted rules
  if (logsource.product === 'windows') {
    return true;
  }

  // Skip rules for non-Windows products
  const nonWindowsProducts = ['linux', 'macos', 'azure', 'gcp', 'aws', 'okta', 'github', 'cisco', 'zeek'];
  if (logsource.product && nonWindowsProducts.includes(logsource.product.toLowerCase())) {
    return false;
  }

  // Skip rules for non-Windows services
  const nonWindowsServices = ['auditd', 'sshd', 'sudo', 'apache', 'nginx'];
  if (logsource.service && nonWindowsServices.includes(logsource.service.toLowerCase())) {
    return false;
  }

  return true;
}

/**
 * Filter rules to only include Windows-compatible ones
 * Call this once before processing to reduce rule count
 */
export function filterWindowsRules(rules: CompiledSigmaRule[]): CompiledSigmaRule[] {
  return rules.filter(rule => isWindowsCompatibleRule(rule.rule.logsource));
}

/**
 * Check if an event's source matches a rule's logsource (legacy - kept for compatibility)
 */
export function matchesLogsource(_event: LogEntry, logsource: SigmaLogSource): boolean {
  return isWindowsCompatibleRule(logsource);
}

/**
 * Build an index of events by EventID for O(1) lookup
 */
export function buildEventIndex(events: LogEntry[]): Map<number | undefined, LogEntry[]> {
  const index = new Map<number | undefined, LogEntry[]>();

  for (const event of events) {
    const eventId = event.eventId;
    const existing = index.get(eventId);
    if (existing) {
      existing.push(event);
    } else {
      index.set(eventId, [event]);
    }
  }

  return index;
}

/**
 * Group rules by their EventID requirements
 */
export interface RuleGroup {
  eventIds: number[] | null; // null means applies to all events
  rules: CompiledSigmaRule[];
}

/**
 * Pre-filter rules to only include those that could match EventIDs present in the EVTX
 * This is a major optimization - if an EVTX only contains EventID 1, we skip all rules
 * that require other EventIDs (like 4688, 7, etc.)
 */
export function filterRulesByAvailableEventIDs(
  rules: CompiledSigmaRule[],
  availableEventIds: Set<number>
): { filteredRules: CompiledSigmaRule[]; skippedCount: number } {
  const filteredRules: CompiledSigmaRule[] = [];
  let skippedCount = 0;

  for (const rule of rules) {
    const ruleEventIds = extractRuleEventIDs(rule);

    if (ruleEventIds === null) {
      // Universal rule - always include
      filteredRules.push(rule);
    } else {
      // Check if ANY of the rule's required EventIDs are in the EVTX
      const hasMatchingEventId = ruleEventIds.some(id => availableEventIds.has(id));
      if (hasMatchingEventId) {
        filteredRules.push(rule);
      } else {
        skippedCount++;
      }
    }
  }

  return { filteredRules, skippedCount };
}

export function groupRulesByEventID(rules: CompiledSigmaRule[]): RuleGroup[] {
  const groups: RuleGroup[] = [];
  const rulesByEventId = new Map<string, CompiledSigmaRule[]>();
  const universalRules: CompiledSigmaRule[] = [];

  for (const rule of rules) {
    // Rules are pre-filtered by platform at load time, no need to filter here
    let eventIds;
    try {
      eventIds = extractRuleEventIDs(rule);
    } catch (e) {
      eventIds = null;
    }

    if (eventIds === null) {
      universalRules.push(rule);
    } else {
      // Create a key from sorted EventIDs
      const key = eventIds.sort((a, b) => a - b).join(',');
      const existing = rulesByEventId.get(key);
      if (existing) {
        existing.push(rule);
      } else {
        rulesByEventId.set(key, [rule]);
      }
    }
  }

  // Add grouped rules
  for (const [key, groupRules] of rulesByEventId) {
    groups.push({
      eventIds: key.split(',').map(Number),
      rules: groupRules
    });
  }

  // Add universal rules (if any)
  if (universalRules.length > 0) {
    groups.push({
      eventIds: null,
      rules: universalRules
    });
  }

  return groups;
}

/**
 * Quick-reject filter for a rule
 * Extracts key field requirements that can be checked quickly
 */
interface QuickFilter {
  field: string;
  type: 'endswith' | 'contains' | 'startswith' | 'equals';
  values: string[];
  lowercase: boolean;
}

/**
 * Extract quick filters from a rule for fast pre-rejection
 * These are fields that MUST match for the rule to possibly match
 */
export function extractQuickFilters(rule: CompiledSigmaRule): QuickFilter[] {
  const filters: QuickFilter[] = [];

  // Priority fields for quick filtering (most discriminating fields by category)
  const priorityFields = [
    // Process creation fields
    'Image', 'CommandLine', 'ParentImage', 'OriginalFileName', 'ParentCommandLine',
    // Registry fields
    'TargetObject', 'Details',
    // Network fields
    'DestinationHostname', 'DestinationIp',
    // File fields
    'TargetFilename'
  ];

  for (const [, selection] of rule.selections) {
    for (const condition of selection.conditions) {
      // Only extract filters for priority fields with string modifiers
      if (!priorityFields.includes(condition.field)) continue;
      if (condition.negate) continue; // Skip negated conditions

      const modifier = condition.modifier;
      if (modifier === 'endswith' || modifier === 'contains' || modifier === 'startswith') {
        const stringValues = condition.values
          .filter((v): v is string => typeof v === 'string')
          .map(v => v.toLowerCase());

        if (stringValues.length > 0) {
          filters.push({
            field: condition.field,
            type: modifier,
            values: stringValues,
            lowercase: true
          });
        }
      }
    }
  }

  return filters;
}

/**
 * Check if an event could possibly match a rule based on quick filters
 * Returns false if we can definitively reject the rule without full matching
 */
function quickRejectCheck(event: LogEntry, filters: QuickFilter[], fieldCache: Map<string, string>): boolean {
  if (filters.length === 0) return true; // No filters, could match

  let anyFieldPresent = false;

  // For OR logic in selections, if ANY filter matches, continue
  // For AND logic, ALL filters must match
  // We'll be conservative and only reject if NO filter can possibly match
  for (const filter of filters) {
    let fieldValue = fieldCache.get(filter.field);

    if (fieldValue === undefined) {
      // Try to extract field value from rawLine
      fieldValue = extractFieldForQuickCheck(event, filter.field);
      fieldCache.set(filter.field, fieldValue);
    }

    if (!fieldValue) continue; // Field not present, skip this filter
    anyFieldPresent = true; // At least one filter field exists in event

    const lowerValue = fieldValue.toLowerCase();

    // Check if ANY of the filter values match
    for (const targetValue of filter.values) {
      let matches = false;
      switch (filter.type) {
        case 'endswith':
          matches = lowerValue.endsWith(targetValue);
          break;
        case 'contains':
          matches = lowerValue.includes(targetValue);
          break;
        case 'startswith':
          matches = lowerValue.startsWith(targetValue);
          break;
      }
      if (matches) return true; // Found a potential match
    }
  }

  // If no filter fields were present in the event, we can't quick-reject (pass through to full matching)
  if (!anyFieldPresent) return true;

  // If we have filters with present fields but none matched, reject
  return false;
}

/**
 * Fast field extraction for quick checks (no full XML parsing)
 */
function extractFieldForQuickCheck(event: LogEntry, field: string): string {
  // Structured EventData (preferred)
  if (event.eventData && event.eventData[field]) {
    return event.eventData[field];
  }

  // First check if it's in the rawLine using regex (faster than DOM parsing)
  const rawLine = event.rawLine;
  if (!rawLine) return '';

  // Try to extract from common Data element patterns
  // <Data Name="Image">C:\Windows\System32\cmd.exe</Data>
  const regex = new RegExp(`<Data Name="${field}"[^>]*>([^<]*)</Data>`, 'i');
  const match = rawLine.match(regex);
  if (match) {
    return match[1];
  }

  return '';
}

/**
 * Optimized matching statistics
 */
export interface OptimizedMatchStats {
  totalEvents: number;
  totalRules: number;
  rulesSkipped: number;
  rulesFilteredByLogsource: number;
  rulesFilteredByEventID: number;
  eventRuleComparisons: number;
  quickRejects: number;
  matchesFound: number;
  processingTimeMs: number;
  indexingTimeMs: number;
}

/**
 * Process events with optimized matching
 * Uses EventID indexing, logsource filtering, field pre-indexing, and quick-reject
 */
export async function processEventsOptimized(
  events: LogEntry[],
  rules: CompiledSigmaRule[],
  onProgress?: (processed: number, total: number, stats: Partial<OptimizedMatchStats>) => void,
  chunkSize: number = 500
): Promise<{ matches: Map<string, SigmaRuleMatch[]>; stats: OptimizedMatchStats }> {
  const startTime = performance.now();
  const matchesByRule = new Map<string, SigmaRuleMatch[]>();

  // Rules are now pre-filtered by platform at load time, no runtime filtering needed
  const rulesFilteredByLogsource = 0;

  // Step 1: Pre-index high-frequency fields for all events
  const indexingStart = performance.now();
  for (const event of events) {
    preIndexEventFields(event);
  }
  const indexingTimeMs = performance.now() - indexingStart;

  // Step 2: Build event index by EventID
  const eventIndex = buildEventIndex(events);

  // Step 2.5: Pre-filter rules by available EventIDs in the EVTX
  // This is a major optimization - skip rules that can never match
  const availableEventIds = new Set<number>();
  for (const eventId of eventIndex.keys()) {
    if (eventId !== undefined) {
      availableEventIds.add(eventId);
    }
  }
  const { filteredRules, skippedCount: rulesFilteredByEventID } = filterRulesByAvailableEventIDs(rules, availableEventIds);

  // Step 3: Group filtered rules by EventID requirements
  const ruleGroups = groupRulesByEventID(filteredRules);

  // Pre-compute quick filters for filtered rules only
  const ruleQuickFilters = new Map<string, QuickFilter[]>();
  for (const rule of filteredRules) {
    ruleQuickFilters.set(rule.rule.id, extractQuickFilters(rule));
  }

  let rulesSkipped = 0;
  let eventRuleComparisons = 0;
  let quickRejects = 0;
  let totalMatches = 0;

  // Calculate total work units (sum of events per rule group)
  let totalWorkUnits = 0;
  for (const group of ruleGroups) {
    if (group.eventIds === null) {
      totalWorkUnits += events.length * group.rules.length;
    } else {
      for (const eventId of group.eventIds) {
        const eventsForId = eventIndex.get(eventId);
        if (eventsForId) {
          totalWorkUnits += eventsForId.length * group.rules.length;
        }
      }
    }
  }
  let completedWorkUnits = 0;

  // Process each rule group
  for (const group of ruleGroups) {
    // Get events that this rule group applies to
    let targetEvents: LogEntry[];

    if (group.eventIds === null) {
      // Universal rules - apply to all events
      targetEvents = events;
    } else {
      // Get events matching any of the group's EventIDs
      targetEvents = [];
      for (const eventId of group.eventIds) {
        const eventsForId = eventIndex.get(eventId);
        if (eventsForId) {
          targetEvents.push(...eventsForId);
        }
      }

      // Skip if no matching events
      if (targetEvents.length === 0) {
        rulesSkipped += group.rules.length;
        continue;
      }
    }

    // Process events in chunks for this rule group
    for (let i = 0; i < targetEvents.length; i += chunkSize) {
      const chunk = targetEvents.slice(i, i + chunkSize);

      for (const event of chunk) {
        // Per-event field cache for quick checks
        const fieldCache = new Map<string, string>();

        for (const rule of group.rules) {
          // Quick-reject check first
          const quickFilters = ruleQuickFilters.get(rule.rule.id) || [];
          if (quickFilters.length > 0 && !quickRejectCheck(event, quickFilters, fieldCache)) {
            quickRejects++;
            completedWorkUnits++;
            continue; // Skip full matching
          }

          eventRuleComparisons++;

          const match = matchRule(event, rule);
          if (match) {
            const existing = matchesByRule.get(match.rule.id) || [];
            existing.push(match);
            matchesByRule.set(match.rule.id, existing);
            totalMatches++;
          }

          completedWorkUnits++;
        }
      }

      // Report progress based on work units, not just events
      if (onProgress) {
        onProgress(completedWorkUnits, totalWorkUnits, {
          rulesSkipped,
          eventRuleComparisons,
          quickRejects,
          matchesFound: totalMatches
        });
      }

      // Yield to browser - use longer delay if document is hidden (background tab)
      // Background tabs throttle setTimeout to 1000ms, so we might as well do more work per chunk
      const isBackground = typeof document !== 'undefined' && document.hidden;
      if (!isBackground) {
        await new Promise(resolve => setTimeout(resolve, 0));
      }
      // If background, skip the delay and do more work in this tick
    }
  }

  // No cleanup needed - we only add rules that have matches

  const stats: OptimizedMatchStats = {
    totalEvents: events.length,
    totalRules: rules.length,
    rulesSkipped,
    rulesFilteredByLogsource,
    rulesFilteredByEventID,
    eventRuleComparisons,
    quickRejects,
    matchesFound: totalMatches,
    processingTimeMs: performance.now() - startTime,
    indexingTimeMs
  };

  return { matches: matchesByRule, stats };
}

/**
 * Calculate theoretical comparisons saved
 */
export function calculateOptimizationGain(
  events: LogEntry[],
  rules: CompiledSigmaRule[]
): { naiveComparisons: number; optimizedEstimate: number; savingsPercent: number } {
  const naiveComparisons = events.length * rules.length;

  const eventIndex = buildEventIndex(events);
  const ruleGroups = groupRulesByEventID(rules);

  let optimizedEstimate = 0;

  for (const group of ruleGroups) {
    if (group.eventIds === null) {
      // Universal rules still check all events
      optimizedEstimate += events.length * group.rules.length;
    } else {
      // Only count events with matching EventIDs
      let matchingEvents = 0;
      for (const eventId of group.eventIds) {
        const eventsForId = eventIndex.get(eventId);
        if (eventsForId) {
          matchingEvents += eventsForId.length;
        }
      }
      optimizedEstimate += matchingEvents * group.rules.length;
    }
  }

  const savingsPercent = naiveComparisons > 0
    ? Math.round((1 - optimizedEstimate / naiveComparisons) * 100)
    : 0;

  return {
    naiveComparisons,
    optimizedEstimate,
    savingsPercent
  };
}
