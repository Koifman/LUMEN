/**
 * SIGMA Rule Matcher
 *
 * Matches events against compiled SIGMA rules
 */

import { CompiledSigmaRule, CompiledRuleStatics, CompiledSelection, ConditionNode, SigmaRuleMatch, SelectionMatchResult, FieldMatchResult } from '../types';
import { applyModifier } from './modifiers';
import { expandPattern } from '../parser/conditionParser';
import { extractRuleEventIDs, matchesExpectedProvider } from './optimizedMatcher';

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

// Lowercased set for O(1) membership checks in the per-event indexing loop
const HIGH_FREQUENCY_FIELDS_LOWER = new Set(HIGH_FREQUENCY_FIELDS.map(f => f.toLowerCase()));

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

  // Prefer structured eventData if available
  if (event.eventData && typeof event.eventData === 'object') {
    for (const [name, value] of Object.entries(event.eventData)) {
      const keyLower = name.toLowerCase();
      if (isSecurity4688 && SYS_MON_METADATA_FIELDS.has(keyLower)) continue;
      if (HIGH_FREQUENCY_FIELDS_LOWER.has(keyLower)) {
        const val =
          typeof value === 'string' || typeof value === 'number'
            ? value
            : value != null
              ? String(value)
              : undefined;
        if (val !== undefined) {
          indexed[name as keyof IndexedFields] = val;
        }
      }
    }
  } else {
    // Parse EventData XML once if present as a fallback
    const xml = event.rawLine;
    if (xml && typeof xml === 'string' && xml.includes('<EventData')) {
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
              if (isSecurity4688 && SYS_MON_METADATA_FIELDS.has(keyLower)) {
                continue;
              }
              if (HIGH_FREQUENCY_FIELDS_LOWER.has(keyLower)) {
                indexed[name as keyof IndexedFields] = value;
              }
            }
          }
        }
      } catch (e) {
        // If parsing fails, fall back to no pre-indexing for this event
      }
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
 * Check if a condition is negation-only (contains only NOT operations)
 * Handles complex cases like "not selection and not selection1" (AND of NOTs)
 * Returns true if all leaf selections are negated
 */
function isNegationOnlyCondition(node: ConditionNode): boolean {
  switch (node.type) {
    case 'NOT':
      // A NOT node is negation-only
      return true;

    case 'AND':
    case 'OR':
      // AND/OR is negation-only if ALL children are negation-only
      if (!node.children || node.children.length === 0) {
        return false;
      }
      return node.children.every(child => isNegationOnlyCondition(child));

    case 'SELECTION':
    case 'ONE_OF':
    case 'ALL_OF':
      // These are positive matches, not negations
      return false;

    default:
      return false;
  }
}

/**
 * Extract all field names referenced in a condition
 * Recursively traverses condition tree and collects fields from all selections
 */
function extractFieldsFromCondition(
  node: ConditionNode,
  selections: Map<string, CompiledSelection>
): string[] {
  const fields: string[] = [];

  function traverse(n: ConditionNode): void {
    switch (n.type) {
      case 'SELECTION': {
        const selectionName = String(n.value);
        const selection = selections.get(selectionName);
        if (selection) {
          for (const condition of selection.conditions) {
            fields.push(condition.field);
          }
        }
        break;
      }

      case 'AND':
      case 'OR':
      case 'NOT':
        if (n.children) {
          for (const child of n.children) {
            traverse(child);
          }
        }
        break;

      case 'ONE_OF':
      case 'ALL_OF': {
        // Expand pattern and collect fields from matching selections
        const pattern = n.pattern || '';
        const matchingSelections = expandPattern(pattern, Array.from(selections.keys()));
        for (const selName of matchingSelections) {
          const selection = selections.get(selName);
          if (selection) {
            for (const condition of selection.conditions) {
              fields.push(condition.field);
            }
          }
        }
        break;
      }
    }
  }

  traverse(node);
  return fields;
}

/**
 * Check if event has at least one of the specified fields
 * Uses the same field extraction logic as extractField() to ensure consistency
 */
function hasAnyField(event: any, fields: string[]): boolean {
  for (const field of fields) {
    const value = extractField(event, field);
    if (value !== undefined) {
      return true;
    }
  }
  return false;
}

/**
 * Build (once) and cache the rule-static analysis results on the compiled rule.
 * All of these depend only on the rule, so computing them per event×rule pair
 * (as matchRule previously did) is pure overhead on the hot path.
 */
export function getRuleStatics(compiledRule: CompiledSigmaRule): CompiledRuleStatics {
  if (compiledRule.statics) {
    return compiledRule.statics;
  }

  const selectionNames = Array.from(compiledRule.selections.keys());

  // Pre-expand ONE_OF/ALL_OF patterns (expandPattern builds a RegExp per call)
  const patternExpansions = new Map<string, string[]>();
  (function collect(node: ConditionNode) {
    if ((node.type === 'ONE_OF' || node.type === 'ALL_OF') && node.pattern) {
      if (!patternExpansions.has(node.pattern)) {
        patternExpansions.set(node.pattern, expandPattern(node.pattern, selectionNames));
      }
    }
    if (node.children) {
      node.children.forEach(collect);
    }
  })(compiledRule.condition);

  const eventIds = extractRuleEventIDs(compiledRule);
  const isNegationOnly = isNegationOnlyCondition(compiledRule.condition);
  const ruleProduct = compiledRule.rule.logsource?.product?.toLowerCase();

  const statics: CompiledRuleStatics = {
    eventIds,
    eventIdSet: eventIds ? new Set(eventIds) : null,
    productIncompatible: !!ruleProduct && ruleProduct !== 'windows' && ruleProduct !== 'win',
    usesSysmonOnlyFields: ruleUsesSysmonOnlyFields(compiledRule),
    isNegationOnly,
    negationRequiredFields: isNegationOnly
      ? extractFieldsFromCondition(compiledRule.condition, compiledRule.selections)
      : [],
    selectionNames,
    patternExpansions,
    requiredSelections: computeRequiredSelections(compiledRule.condition, patternExpansions)
  };

  compiledRule.statics = statics;
  return statics;
}

/**
 * Compute the set of selections that MUST evaluate to true for the condition
 * to be satisfiable. Used to build sound quick-reject filters: only conditions
 * from these selections can be treated as mandatory.
 *
 * - AND: union of children's required sets (all children must hold)
 * - OR: intersection (only selections required by every branch are certain)
 * - NOT / COUNT: nothing is required to be TRUE (negated or threshold logic)
 * - ALL_OF: every expanded selection is required
 * - ONE_OF: only required if the pattern expands to exactly one selection
 */
function computeRequiredSelections(
  node: ConditionNode,
  patternExpansions: Map<string, string[]>
): Set<string> {
  switch (node.type) {
    case 'SELECTION':
      return new Set([String(node.value)]);

    case 'AND': {
      const result = new Set<string>();
      for (const child of node.children || []) {
        for (const sel of computeRequiredSelections(child, patternExpansions)) {
          result.add(sel);
        }
      }
      return result;
    }

    case 'OR': {
      const children = node.children || [];
      if (children.length === 0) {
        return new Set();
      }
      let intersection: Set<string> | null = null;
      for (const child of children) {
        const childSet = computeRequiredSelections(child, patternExpansions);
        if (intersection === null) {
          intersection = childSet;
        } else {
          const kept: string[] = [];
          for (const sel of intersection) {
            if (childSet.has(sel)) {
              kept.push(sel);
            }
          }
          intersection = new Set<string>(kept);
        }
        if (intersection.size === 0) {
          return intersection;
        }
      }
      return intersection || new Set<string>();
    }

    case 'ALL_OF':
      return new Set(patternExpansions.get(node.pattern || '') || []);

    case 'ONE_OF': {
      const expanded = patternExpansions.get(node.pattern || '') || [];
      return expanded.length === 1 ? new Set(expanded) : new Set();
    }

    default:
      // NOT, COUNT: no selection is required to be true
      return new Set();
  }
}

/**
 * Match an event against a compiled rule
 */
export function matchRule(event: any, compiledRule: CompiledSigmaRule): SigmaRuleMatch | null {
  const statics = getRuleStatics(compiledRule);
  const isSecurity4688 = event?.eventId === 4688;

  // Skip rules that rely on Sysmon-only metadata for Security 4688 events
  if (isSecurity4688 && statics.usesSysmonOnlyFields) {
    return null;
  }

  // CRITICAL FIX: Check if event EventID matches rule's logsource category requirements
  // This prevents false positives from rules with negation logic (e.g., "not Image|contains")
  // matching events that don't have the expected fields at all (e.g., RPC logs)
  if (statics.eventIdSet !== null && statics.eventIdSet.size > 0) {
    const eventId = event?.eventId;
    if (eventId === undefined || !statics.eventIdSet.has(eventId)) {
      // Event doesn't match the required EventIDs for this rule's logsource category
      return null;
    }
  }

  // CRITICAL FIX: Logsource product validation
  // Prevents cross-platform rules from matching incompatible events
  // Example: Azure sign-in rules (product: azure) should not match Windows events
  if (statics.productIncompatible) {
    return null;
  }

  // CRITICAL FIX (Issue #34): Check if event provider matches expected provider for category+EventID
  // Prevents false positives like RPC Event ID 1 matching process_creation rules (Sysmon Event ID 1)
  if (!matchesExpectedProvider(event, compiledRule)) {
    return null;
  }

  // CRITICAL FIX: Field existence validation for negation-only rules
  // Prevents false positives when rules with pure negation (e.g., "not selection") match events
  // that don't have ANY of the selection's fields (e.g., Zeek rules matching EVTX logs)
  // Example: Zeek RDP rule with "not id.orig_h|cidr: [...]" should not match Windows events
  // that lack id.orig_h field entirely
  if (statics.isNegationOnly) {
    if (statics.negationRequiredFields.length > 0 && !hasAnyField(event, statics.negationRequiredFields)) {
      // Event doesn't have any of the fields referenced in negation-only condition
      // Skip this rule to prevent false positive
      return null;
    }
  }

  // Fast path: evaluate the condition with lazy, memoized, boolean-only selection
  // evaluation. Selections not needed to decide the condition are never evaluated,
  // and no per-field result objects are allocated for the (overwhelmingly common)
  // non-matching case.
  const boolMemo = new Map<string, boolean>();
  const conditionMatched = evaluateConditionLazy(
    compiledRule.condition,
    event,
    compiledRule,
    statics,
    boolMemo
  );

  if (!conditionMatched) {
    return null;
  }

  // Slow path (rare): the rule matched — re-evaluate all selections with full
  // field-level detail for UI display. Field extraction is cached per event,
  // so this second pass does not re-parse anything.
  const selectionResults = new Map<string, SelectionMatchResult>();

  for (const [name, selection] of compiledRule.selections) {
    const result = evaluateSelection(event, selection);
    selectionResults.set(name, result);
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
 * Boolean-only twin of evaluateSelection for the hot path: identical matching
 * semantics (including the Security-4688 Sysmon-field skip), but allocates no
 * per-field result objects and short-circuits as soon as the outcome is known.
 */
function evaluateSelectionBool(event: any, selection: CompiledSelection): boolean {
  let anyConditionMatched = false;
  let allConditionsMatched = true;
  const isSecurity4688 = event?.eventId === 4688;

  for (const condition of selection.conditions) {
    // Skip Sysmon-only fields for Security 4688 events
    if (isSecurity4688 && isSysmonOnlyField(condition.field)) {
      allConditionsMatched = false;
      if (!selection.useOrLogic) return false;
      continue;
    }

    const fieldValue = extractField(event, condition.field);
    let matched = false;

    if (condition.requireAll) {
      matched = condition.values.every((targetValue: string | number | null) =>
        applyModifier(fieldValue, targetValue, condition.modifier)
      );
    } else {
      for (const targetValue of condition.values) {
        if (applyModifier(fieldValue, targetValue, condition.modifier)) {
          matched = true;
          break;
        }
      }
    }

    if (condition.negate) {
      matched = !matched;
    }

    if (matched) {
      anyConditionMatched = true;
      if (selection.useOrLogic) return true;
    } else {
      allConditionsMatched = false;
      if (!selection.useOrLogic) return false;
    }
  }

  return selection.useOrLogic ? anyConditionMatched : allConditionsMatched;
}

/**
 * Get a selection's boolean match result, evaluating it at most once per event
 * (memoized in `memo`). Selections referenced in the condition but not defined
 * evaluate to false, matching the previous behavior.
 */
function getSelectionResultBool(
  name: string,
  event: any,
  compiledRule: CompiledSigmaRule,
  memo: Map<string, boolean>
): boolean {
  let result = memo.get(name);
  if (result === undefined) {
    const selection = compiledRule.selections.get(name);
    result = selection ? evaluateSelectionBool(event, selection) : false;
    memo.set(name, result);
  }
  return result;
}

/**
 * Evaluate condition AST lazily: selections are only evaluated when the
 * logical structure actually needs their result, and only as booleans.
 * Pattern expansions come precomputed from rule statics.
 */
function evaluateConditionLazy(
  node: ConditionNode,
  event: any,
  compiledRule: CompiledSigmaRule,
  statics: CompiledRuleStatics,
  memo: Map<string, boolean>
): boolean {
  switch (node.type) {
    case 'AND':
      return node.children?.every(child =>
        evaluateConditionLazy(child, event, compiledRule, statics, memo)
      ) ?? false;

    case 'OR':
      return node.children?.some(child =>
        evaluateConditionLazy(child, event, compiledRule, statics, memo)
      ) ?? false;

    case 'NOT':
      return !evaluateConditionLazy(node.children![0], event, compiledRule, statics, memo);

    case 'SELECTION':
      return getSelectionResultBool(String(node.value), event, compiledRule, memo);

    case 'ONE_OF': {
      const matchingSelections = statics.patternExpansions.get(node.pattern || '') || [];
      return matchingSelections.some(sel =>
        getSelectionResultBool(sel, event, compiledRule, memo)
      );
    }

    case 'ALL_OF': {
      const matchingSelections = statics.patternExpansions.get(node.pattern || '') || [];
      return matchingSelections.every(sel =>
        getSelectionResultBool(sel, event, compiledRule, memo)
      );
    }

    case 'COUNT': {
      const count = getSelectionResultBool(String(node.value), event, compiledRule, memo) ? 1 : 0;
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

  // Structured EventData map (preferred, no XML parsing)
  if (event.eventData && fieldPath in event.eventData) {
    return event.eventData[fieldPath];
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

  // Check alternative field names in structured eventData (for WASM-parsed events)
  const alternativeFields = sigmaFieldMappings[fieldPath];
  if (alternativeFields && event.eventData) {
    for (const altField of alternativeFields) {
      if (altField in event.eventData) {
        return event.eventData[altField];
      }
    }
  }

  // Parse EventData fields from rawLine XML (with caching) - slow path
  if (event.rawLine && typeof event.rawLine === 'string' && event.rawLine.includes('<')) {
    let value = extractFromEventData(event, fieldPath);
    if (value !== undefined) {
      return value;
    }

    // Check alternative field names via XML parsing (for XML-parsed events)
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
  // Use structured eventData first
  if (event.eventData && fieldName in event.eventData) {
    return event.eventData[fieldName];
  }

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
 *
 * Performance improvement: 2-5x faster for large datasets (100k+ events)
 * by pre-indexing high-frequency fields before rule matching
 */
export function matchAllEventsOptimized(
  events: any[],
  rules: CompiledSigmaRule[]
): Map<string, SigmaRuleMatch[]> {
  // Pre-index all events upfront
  // This parses EventData fields once per event instead of once per rule per event
  for (const event of events) {
    preIndexEventFields(event);
  }

  // Use standard matching (now faster because fields are cached)
  return matchAllEvents(events, rules);
}
