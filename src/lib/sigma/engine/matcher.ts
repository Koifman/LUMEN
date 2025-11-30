/**
 * SIGMA Rule Matcher
 *
 * Matches events against compiled SIGMA rules
 */

import { CompiledSigmaRule, ConditionNode, SigmaRuleMatch, SelectionMatchResult, FieldMatchResult } from '../types';
import { applyModifier } from './modifiers';
import { expandPattern } from '../parser/conditionParser';

// Cache for parsed EventData to avoid repeated XML parsing
const eventDataCache = new WeakMap<object, Map<string, string | undefined>>();

// Pre-indexed field cache for high-frequency fields (parsed upfront)
const indexedFieldCache = new WeakMap<object, IndexedFields>();

/**
 * Pre-indexed fields structure for fast access
 */
export interface IndexedFields {
  EventID?: number;
  Image?: string;
  CommandLine?: string;
  ParentImage?: string;
  ParentCommandLine?: string;
  OriginalFileName?: string;
  User?: string;
  TargetFilename?: string;
  SourceImage?: string;
  TargetImage?: string;
  Computer?: string;
  Provider?: string;
  [key: string]: string | number | undefined;
}

/**
 * High-frequency fields to pre-index (in order of importance for SIGMA rules)
 */
const HIGH_FREQUENCY_FIELDS = [
  'Image', 'CommandLine', 'ParentImage', 'ParentCommandLine',
  'OriginalFileName', 'User', 'TargetFilename', 'SourceImage',
  'TargetImage', 'Hashes', 'Company', 'Description', 'Product',
  'IntegrityLevel', 'CurrentDirectory', 'LogonId',
  // Registry fields (for registry_set, registry_event rules - Sysmon EID 12, 13, 14)
  'TargetObject', 'Details', 'EventType'
];

/**
 * Pre-index high-frequency fields for an event
 * Call this once per event before rule matching for optimal performance
 */
export function preIndexEventFields(event: any): IndexedFields {
  // Check cache first
  const cached = indexedFieldCache.get(event);
  if (cached) return cached;

  const indexed: IndexedFields = {};
  const isSecurity4688 = event?.eventId === 4688;

  // Direct field mappings
  if (event.eventId !== undefined) indexed.EventID = event.eventId;
  if (event.computer !== undefined) indexed.Computer = event.computer;
  if (event.source !== undefined) indexed.Provider = event.source;

  // Parse EventData XML once if present
  const xml = event.rawLine;
  if (xml && typeof xml === 'string' && xml.includes('<EventData')) {
    // Parse once and cache values for all Data elements (case-insensitive)
    try {
      const parser = new DOMParser();
      const doc = parser.parseFromString(xml, 'text/xml');
      const parserError = doc.querySelector('parsererror');
      if (!parserError) {
        const eventData = doc.querySelector('EventData');
        if (eventData) {
          const dataElements = eventData.querySelectorAll('Data');
          for (const dataElem of Array.from(dataElements)) {
            const name = dataElem.getAttribute('Name');
            if (!name) continue;
            const value = (dataElem.textContent || '').trim();
            const keyLower = name.toLowerCase();
            // Skip Sysmon-only metadata when handling Security 4688 events
            if (isSecurity4688 && SYS_MON_METADATA_FIELDS.has(keyLower)) {
              continue;
            }
            if (HIGH_FREQUENCY_FIELDS.some(f => f.toLowerCase() === keyLower)) {
              indexed[name as keyof IndexedFields] = value;
            }
          }
        }
      }
    } catch (e) {
      // If parsing fails, fall back to no pre-indexing for this event
    }
  }

  indexedFieldCache.set(event, indexed);
  return indexed;
}

/**
 * Get pre-indexed field value (fast path)
 */
export function getIndexedField(event: any, fieldName: string): string | number | undefined {
  const indexed = indexedFieldCache.get(event);
  if (indexed && fieldName in indexed) {
    return indexed[fieldName];
  }
  return undefined;
}

/**
 * Clear indexed cache for an event (if needed)
 */
export function clearIndexedCache(event: any): void {
  indexedFieldCache.delete(event);
}

/**
 * Match an event against a compiled rule
 */
export function matchRule(event: any, compiledRule: CompiledSigmaRule): SigmaRuleMatch | null {
  const isSecurity4688 = event?.eventId === 4688;

  // Skip rules that rely on Sysmon-only metadata for Security 4688 events
  if (isSecurity4688 && ruleUsesSysmonOnlyFields(compiledRule)) {
    return null;
  }

  // Evaluate all selections
  const selectionResults = new Map<string, SelectionMatchResult>();

  for (const [name, selection] of compiledRule.selections) {
    const result = evaluateSelection(event, selection);
    selectionResults.set(name, result);
  }

  // Evaluate condition
  const conditionMatched = evaluateCondition(
    compiledRule.condition,
    selectionResults,
    Array.from(compiledRule.selections.keys())
  );

  if (!conditionMatched) {
    return null;
  }

  // ALWAYS include ALL selections (not just matched ones) so users can see full context
  // This is important for rules with NOT/filter conditions where users need to see
  // what fields were evaluated even if they didn't match
  // Example: "Uncommon svchost Command Line" - users need to see CommandLine value
  // even though it's only in filter selections that explicitly did NOT match
  const matchedSelections: SelectionMatchResult[] = [];
  for (const result of selectionResults.values()) {
    // For Security 4688 events, strip Sysmon-only field matches to avoid noise
    const filteredFieldMatches = isSecurity4688
      ? result.fieldMatches.filter(fm => !isSysmonOnlyField(fm.field))
      : result.fieldMatches;

    // If nothing remains and the selection didn't match, skip adding it
    if (isSecurity4688 && filteredFieldMatches.length === 0 && !result.matched) {
      continue;
    }

    matchedSelections.push({
      ...result,
      fieldMatches: filteredFieldMatches
    });
  }

  // Use the event's timestamp, not current time
  const eventTimestamp = event.timestamp instanceof Date
    ? event.timestamp
    : (event.timestamp ? new Date(event.timestamp) : new Date());

  return {
    rule: compiledRule.rule,
    matched: true,
    selectionMatches: matchedSelections,
    event,
    timestamp: eventTimestamp,
    compiledRule // Include compiled rule for UI access to selection definitions
  };
}

/**
 * Evaluate a selection against an event
 */
function evaluateSelection(event: any, selection: any): SelectionMatchResult {
  const fieldMatches: FieldMatchResult[] = [];
  let anyConditionMatched = false;
  let allConditionsMatched = true;
  const isSecurity4688 = event?.eventId === 4688;

  for (const condition of selection.conditions) {
    // Skip Sysmon-only fields for Security 4688 events
    if (isSecurity4688 && isSysmonOnlyField(condition.field)) {
      allConditionsMatched = false;
      continue;
    }

    const fieldValue = extractField(event, condition.field);
    let matched = false;
    let matchedPattern: string | number | null | (string | number | null)[] | undefined = undefined;

    // If requireAll is true, ALL values must match
    if (condition.requireAll) {
      matched = condition.values.every((targetValue: string | number | null) =>
        applyModifier(fieldValue, targetValue, condition.modifier)
      );
      // For requireAll, store all values since they all must match
      if (matched && condition.values.length > 0) {
        matchedPattern = condition.values.length === 1 ? condition.values[0] : condition.values;
      }
    } else {
      // Default: ANY value matches
      for (const targetValue of condition.values) {
        if (applyModifier(fieldValue, targetValue, condition.modifier)) {
          matched = true;
          matchedPattern = targetValue; // Track which specific value matched
          break;
        }
      }
    }

    // Apply negation if needed
    if (condition.negate) {
      matched = !matched;
      // For negated conditions, we don't show a specific matched pattern
      matchedPattern = undefined;
    }

    fieldMatches.push({
      field: condition.field,
      value: fieldValue,
      matched,
      modifier: condition.modifier,
      matchedPattern
    });

    if (matched) {
      anyConditionMatched = true;
    }
    if (!matched) {
      allConditionsMatched = false;
    }
  }

  // Use OR logic for array-based selections, AND logic otherwise
  const selectionMatched = selection.useOrLogic ? anyConditionMatched : allConditionsMatched;

  return {
    selection: selection.name,
    matched: selectionMatched,
    fieldMatches
  };
}

/**
 * Evaluate condition AST
 */
function evaluateCondition(
  node: ConditionNode,
  selectionResults: Map<string, SelectionMatchResult>,
  availableSelections: string[]
): boolean {
  switch (node.type) {
    case 'AND':
      return node.children?.every(child =>
        evaluateCondition(child, selectionResults, availableSelections)
      ) ?? false;

    case 'OR':
      return node.children?.some(child =>
        evaluateCondition(child, selectionResults, availableSelections)
      ) ?? false;

    case 'NOT':
      return !evaluateCondition(
        node.children![0],
        selectionResults,
        availableSelections
      );

    case 'SELECTION': {
      const selectionName = String(node.value);
      const result = selectionResults.get(selectionName);
      return result?.matched ?? false;
    }

    case 'ONE_OF': {
      const pattern = node.pattern || '';
      const matchingSelections = expandPattern(pattern, availableSelections);
      return matchingSelections.some(sel => {
        const result = selectionResults.get(sel);
        return result?.matched ?? false;
      });
    }

    case 'ALL_OF': {
      const pattern = node.pattern || '';
      const matchingSelections = expandPattern(pattern, availableSelections);
      return matchingSelections.every(sel => {
        const result = selectionResults.get(sel);
        return result?.matched ?? false;
      });
    }

    case 'COUNT': {
      const selectionName = String(node.value);
      const result = selectionResults.get(selectionName);
      const count = result?.matched ? 1 : 0;
      const threshold = node.threshold || 0;
      const operator = node.operator || '>';

      switch (operator) {
        case '>': return count > threshold;
        case '<': return count < threshold;
        case '>=': return count >= threshold;
        case '<=': return count <= threshold;
        case '==': return count === threshold;
        default: return false;
      }
    }

    default:
      return false;
  }
}

/**
 * Extract field from event
 * Uses indexed cache for high-frequency fields, falls back to DOM parsing for others
 */
function extractField(event: any, fieldPath: string): any {
  // Fast path: check pre-indexed cache first (O(1) lookup)
  const indexedValue = getIndexedField(event, fieldPath);
  if (indexedValue !== undefined) {
    return indexedValue;
  }

  // Direct field access
  if (fieldPath in event) {
    return event[fieldPath];
  }

  // Check common field mappings to LogEntry fields
  const fieldMappings: Record<string, string> = {
    'Provider': 'source',
    'EventID': 'eventId',
    'Computer': 'computer'
  };

  const mappedField = fieldMappings[fieldPath];
  if (mappedField && mappedField in event) {
    return event[mappedField];
  }

  // Parse EventData fields from rawLine XML (with caching) - slow path
  if (event.rawLine && typeof event.rawLine === 'string' && event.rawLine.includes('<')) {
    let value = extractFromEventData(event, fieldPath);
    if (value !== undefined) {
      return value;
    }

    // SIGMA field name translation: Sysmon -> Windows Security Event Log
    // Many SIGMA rules use Sysmon field names, but we need to support Windows Security logs too
    const sigmaFieldMappings: Record<string, string[]> = {
      // Process Creation (Sysmon EID 1 vs Security EID 4688)
      'Image': ['NewProcessName'],
      'ParentImage': ['ParentProcessName'],
      'CommandLine': ['CommandLine', 'ProcessCommandLine'],
      'ParentCommandLine': ['ParentProcessCommandLine'],
      'User': ['SubjectUserName', 'TargetUserName'],
      'LogonId': ['SubjectLogonId', 'TargetLogonId'],
      'IntegrityLevel': ['MandatoryLabel'],
      // File operations
      'TargetFilename': ['ObjectName'],
      // Registry operations
      'TargetObject': ['ObjectName'],
      // Network
      'SourceIp': ['IpAddress', 'SourceAddress'],
      'DestinationIp': ['DestAddress']
    };

    const alternativeFields = sigmaFieldMappings[fieldPath];
    if (alternativeFields) {
      for (const altField of alternativeFields) {
        value = extractFromEventData(event, altField);
        if (value !== undefined) {
          return value;
        }
      }
    }
  }

  // Handle nested paths with dot notation
  const parts = fieldPath.split('.');
  let current = event;

  for (const part of parts) {
    if (current && typeof current === 'object' && part in current) {
      current = current[part];
    } else {
      return undefined;
    }
  }

  return current;
}

/**
 * Extract field from EventData XML section with caching
 */
function extractFromEventData(event: any, fieldName: string): string | undefined {
  // Check cache first
  let fieldCache = eventDataCache.get(event);
  if (fieldCache) {
    if (fieldCache.has(fieldName)) {
      return fieldCache.get(fieldName);
    }
  } else {
    fieldCache = new Map();
    eventDataCache.set(event, fieldCache);
  }

  const xml = event.rawLine;
  if (!xml || typeof xml !== 'string') {
    fieldCache.set(fieldName, undefined);
    return undefined;
  }

  // Parse and cache all relevant fields once (DOM is more reliable than regex across formats)
  try {
    if (!fieldCache.has('__parsed__')) {
      const parser = new DOMParser();
      const doc = parser.parseFromString(xml, 'text/xml');

      const parserError = doc.querySelector('parsererror');
      if (parserError) {
        fieldCache.set('__parsed__', undefined);
        fieldCache.set(fieldName, undefined);
        return undefined;
      }

      // Helper to store value with case-insensitive keys
      const storeValue = (name: string, value: string | undefined) => {
        const trimmed = value?.trim();
        fieldCache!.set(name, trimmed);
        fieldCache!.set(name.toLowerCase(), trimmed);
      };

      // EventData: <Data Name="X">value</Data> and direct child elements
      const eventData = doc.querySelector('EventData');
      if (eventData) {
        const dataElements = eventData.querySelectorAll('Data');
        for (const dataElem of Array.from(dataElements)) {
          const name = dataElem.getAttribute('Name');
          if (!name) continue;
          storeValue(name, dataElem.textContent || undefined);
        }

        // Direct child tags (e.g., <CommandLine>value</CommandLine>)
        for (const child of Array.from(eventData.children)) {
          if (child.tagName === 'Data') continue;
          storeValue(child.tagName, child.textContent || undefined);
        }
      }

      // UserData fields
      const userData = doc.querySelector('UserData');
      if (userData) {
        const children = userData.children;
        for (const child of Array.from(children)) {
          const grandChildren = child.children;
          for (const gc of Array.from(grandChildren)) {
            storeValue(gc.tagName, gc.textContent || undefined);
          }
        }
      }

      fieldCache.set('__parsed__', 'done');
    }

    // Skip Sysmon-only metadata when processing Security 4688 events
    const isSecurity4688 = event?.eventId === 4688;
    if (isSecurity4688 && SYS_MON_METADATA_FIELDS.has(fieldName.toLowerCase())) {
      fieldCache.set(fieldName, undefined);
      return undefined;
    }

    return fieldCache.get(fieldName) ?? fieldCache.get(fieldName.toLowerCase());
  } catch (e) {
    fieldCache.set(fieldName, undefined);
    return undefined;
  }
}

// Sysmon-only metadata fields that should not be considered for Security 4688 events
const SYS_MON_METADATA_FIELDS = new Set([
  'product',
  'company',
  'originalfilename'
]);

function isSysmonOnlyField(fieldName: string): boolean {
  return SYS_MON_METADATA_FIELDS.has(fieldName.toLowerCase());
}

function ruleUsesSysmonOnlyFields(compiledRule: CompiledSigmaRule): boolean {
  for (const selection of compiledRule.selections.values()) {
    for (const condition of selection.conditions) {
      if (isSysmonOnlyField(condition.field)) {
        return true;
      }
    }
  }
  return false;
}

/**
 * Match event against multiple rules
 */
export function matchRules(event: any, rules: CompiledSigmaRule[]): SigmaRuleMatch[] {
  const matches: SigmaRuleMatch[] = [];

  for (const rule of rules) {
    const match = matchRule(event, rule);
    if (match) {
      matches.push(match);
    }
  }

  return matches;
}

/**
 * Match multiple events against multiple rules
 */
export function matchAllEvents(
  events: any[],
  rules: CompiledSigmaRule[]
): Map<string, SigmaRuleMatch[]> {
  const matchesByRule = new Map<string, SigmaRuleMatch[]>();

  // Initialize map
  for (const rule of rules) {
    matchesByRule.set(rule.rule.id, []);
  }

  // Match each event
  for (const event of events) {
    const matches = matchRules(event, rules);

    for (const match of matches) {
      const ruleId = match.rule.id;
      const existing = matchesByRule.get(ruleId) || [];
      existing.push(match);
      matchesByRule.set(ruleId, existing);
    }
  }

  // Remove rules with no matches
  for (const [ruleId, matches] of matchesByRule.entries()) {
    if (matches.length === 0) {
      matchesByRule.delete(ruleId);
    }
  }

  return matchesByRule;
}

/**
 * Performance-optimized batch matching
 * Uses field indexing for faster lookups
 */
export function matchAllEventsOptimized(
  events: any[],
  rules: CompiledSigmaRule[]
): Map<string, SigmaRuleMatch[]> {
  // TODO: Implement field indexing
  // For now, use standard matching
  return matchAllEvents(events, rules);
}
