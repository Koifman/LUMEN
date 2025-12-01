/**
 * SIGMA Detection Engine - MVP
 *
 * Simplified SIGMA rule matching engine
 * Matches log entries against detection rules
 */

import { LogEntry } from '../types';
import { SimpleSigmaRule } from './sigmaRules';

export interface FieldMatch {
  field: string;
  value: string;
}

export interface SigmaMatch {
  rule: SimpleSigmaRule;
  event: LogEntry;
  matchedFields: string[];
  fieldMatches: FieldMatch[]; // Detailed field + value pairs
}

/**
 * Match a single event against all rules
 * Returns all matching rules
 */
export function matchEvent(event: LogEntry, rules: SimpleSigmaRule[]): SigmaMatch[] {
  const matches: SigmaMatch[] = [];

  for (const rule of rules) {
    const matchResult = matchEventAgainstRule(event, rule);
    if (matchResult) {
      matches.push(matchResult);
    }
  }

  return matches;
}

/**
 * Match all events against all rules
 * Returns grouped matches by rule
 */
export function matchAllEvents(
  events: LogEntry[],
  rules: SimpleSigmaRule[]
): Map<string, SigmaMatch[]> {
  const matchesByRule = new Map<string, SigmaMatch[]>();

  // Initialize map
  for (const rule of rules) {
    matchesByRule.set(rule.id, []);
  }

  // Match each event
  for (const event of events) {
    const matches = matchEvent(event, rules);

    for (const match of matches) {
      const existing = matchesByRule.get(match.rule.id) || [];
      existing.push(match);
      matchesByRule.set(match.rule.id, existing);
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
 * Match a single event against a single rule
 */
function matchEventAgainstRule(
  event: LogEntry,
  rule: SimpleSigmaRule
): SigmaMatch | null {
  const matchedFields: string[] = [];
  const fieldMatches: FieldMatch[] = [];
  const detection = rule.detection;

  // Check EventID
  if (detection.eventId !== undefined) {
    const ruleEventIds = Array.isArray(detection.eventId)
      ? detection.eventId
      : [detection.eventId];

    if (event.eventId && !ruleEventIds.includes(event.eventId)) {
      return null; // EventID doesn't match
    }

    if (event.eventId && ruleEventIds.includes(event.eventId)) {
      matchedFields.push('EventID');
      fieldMatches.push({ field: 'EventID', value: String(event.eventId) });
    }
  }

  // Check Provider
  if (detection.provider !== undefined) {
    const ruleProviders = Array.isArray(detection.provider)
      ? detection.provider
      : [detection.provider];

    const eventSource = event.source || '';

    if (!ruleProviders.some(p => eventSource.includes(p))) {
      return null; // Provider doesn't match
    }

    matchedFields.push('Provider');
    fieldMatches.push({ field: 'Provider', value: eventSource });
  }

  // Check Channel
  if (detection.channel !== undefined) {
    const ruleChannels = Array.isArray(detection.channel)
      ? detection.channel
      : [detection.channel];

    const eventPath = event.path || '';

    if (!ruleChannels.some(c => eventPath.includes(c))) {
      return null; // Channel doesn't match
    }

    matchedFields.push('Channel');
    fieldMatches.push({ field: 'Channel', value: eventPath });
  }

  // Check contains conditions
  if (detection.contains && detection.contains.length > 0) {
    const containsResults = detection.contains.map(condition =>
      matchContainsCondition(event, condition)
    );

    if (detection.logic === 'and') {
      // All contains conditions must match
      if (!containsResults.every(r => r.matched)) {
        return null;
      }
      containsResults.forEach(r => {
        if (r.matchedField) {
          matchedFields.push(r.matchedField);
          if (r.matchedValue) {
            fieldMatches.push({ field: r.matchedField, value: r.matchedValue });
          }
        }
      });
    } else {
      // At least one contains condition must match
      if (!containsResults.some(r => r.matched)) {
        return null;
      }
      containsResults.forEach(r => {
        if (r.matched && r.matchedField) {
          matchedFields.push(r.matchedField);
          if (r.matchedValue) {
            fieldMatches.push({ field: r.matchedField, value: r.matchedValue });
          }
        }
      });
    }
  }

  // Check equals conditions
  if (detection.equals && detection.equals.length > 0) {
    const equalsResults = detection.equals.map(condition =>
      matchEqualsCondition(event, condition)
    );

    if (detection.logic === 'and') {
      if (!equalsResults.every(r => r.matched)) {
        return null;
      }
      equalsResults.forEach(r => {
        if (r.matched && r.field) {
          matchedFields.push(r.field);
          fieldMatches.push({ field: r.field, value: String(r.value) });
        }
      });
    } else {
      if (!equalsResults.some(r => r.matched)) {
        return null;
      }
      equalsResults.forEach(r => {
        if (r.matched && r.field) {
          matchedFields.push(r.field);
          fieldMatches.push({ field: r.field, value: String(r.value) });
        }
      });
    }
  }

  // If we got here, the event matches the rule
  return {
    rule,
    event,
    matchedFields: [...new Set(matchedFields)], // Remove duplicates
    fieldMatches
  };
}

/**
 * Check if event matches a 'contains' condition
 */
function matchContainsCondition(
  event: LogEntry,
  condition: NonNullable<SimpleSigmaRule['detection']['contains']>[0]
): { matched: boolean; matchedField?: string; matchedValue?: string } {
  const fieldValue = getEventField(event, condition.field);

  if (!fieldValue) {
    return { matched: false };
  }

  const fieldStr = String(fieldValue).toLowerCase();
  const matches = condition.values.map(value =>
    fieldStr.includes(value.toLowerCase())
  );

  if (condition.operator === 'any') {
    // Match if any value is found
    const matched = matches.some(m => m);
    return {
      matched,
      matchedField: condition.field,
      matchedValue: matched ? truncateValue(String(fieldValue)) : undefined
    };
  } else {
    // Match if all values are found
    const matched = matches.every(m => m);
    return {
      matched,
      matchedField: condition.field,
      matchedValue: matched ? truncateValue(String(fieldValue)) : undefined
    };
  }
}

/**
 * Check if event matches an 'equals' condition
 */
function matchEqualsCondition(
  event: LogEntry,
  condition: NonNullable<SimpleSigmaRule['detection']['equals']>[0]
): { matched: boolean; field?: string; value?: any } {
  const fieldValue = getEventField(event, condition.field);

  if (fieldValue === undefined || fieldValue === null) {
    return { matched: false };
  }

  const matched = fieldValue === condition.value;
  return {
    matched,
    field: matched ? condition.field : undefined,
    value: matched ? fieldValue : undefined
  };
}

/**
 * Truncate long values for display
 */
function truncateValue(value: string, maxLength: number = 100): string {
  if (value.length <= maxLength) {
    return value;
  }
  return value.substring(0, maxLength) + '...';
}

/**
 * Extract field value from event
 * Supports nested fields using dot notation (e.g., "EventData.CommandLine")
 */
function getEventField(event: LogEntry, fieldPath: string): any {
  // Direct field access
  if (fieldPath in event) {
    return (event as any)[fieldPath];
  }

  // Check common field mappings to LogEntry fields
  const fieldMappings: Record<string, keyof LogEntry | string> = {
    'Provider': 'source',
    'EventID': 'eventId',
    'Computer': 'computer'
  };

  const mappedField = fieldMappings[fieldPath];
  if (mappedField && mappedField in event) {
    return (event as any)[mappedField];
  }

  // Structured EventData map (preferred over XML parsing)
  if (event.eventData && fieldPath in event.eventData) {
    return event.eventData[fieldPath];
  }

  // Parse EventData fields from rawLine XML
  if (event.rawLine && event.rawLine.includes('<')) {
    try {
      const value = extractFromEventData(event.rawLine, fieldPath);
      if (value !== undefined) {
        return value;
      }
    } catch (e) {
      // Continue to fallback methods
    }
  }

  return undefined;
}

/**
 * Extract field from EventData XML section
 * Handles both <Data Name="Field">Value</Data> and <Field>Value</Field> formats
 */
function extractFromEventData(xml: string, fieldName: string): string | undefined {
  // Fast path: catch <Data Name="CommandLine">value</Data> and <CommandLine>value</CommandLine>
  const escapedField = fieldName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const dataRegex = new RegExp(`<Data\\s+[^>]*Name=['"]${escapedField}['"][^>]*>([\\s\\S]*?)<\\/Data>`, 'i');
  const directRegex = new RegExp(`<${escapedField}>([\\s\\S]*?)<\\/${escapedField}>`, 'i');

  const dataMatch = xml.match(dataRegex);
  if (dataMatch && dataMatch[1] !== undefined) {
    return dataMatch[1];
  }

  const directMatch = xml.match(directRegex);
  if (directMatch && directMatch[1] !== undefined) {
    return directMatch[1];
  }

  try {
    const parser = new DOMParser();
    const doc = parser.parseFromString(xml, 'text/xml');

    // Check for parse errors
    const parserError = doc.querySelector('parsererror');
    if (parserError) {
      return undefined;
    }

    // Try EventData > Data[@Name="fieldName"]
    const eventData = doc.querySelector('EventData, EventData');
    if (eventData) {
      // Format 1: <Data Name="CommandLine">value</Data>
      const dataElements = eventData.querySelectorAll('Data');
      for (const dataElem of Array.from(dataElements)) {
        const name = dataElem.getAttribute('Name');
        if (name === fieldName) {
          return dataElem.textContent || undefined;
        }
      }

      // Format 2: <CommandLine>value</CommandLine>
      const directChild = eventData.querySelector(fieldName);
      if (directChild) {
        return directChild.textContent || undefined;
      }
    }

    // Try UserData section
    const userData = doc.querySelector('UserData');
    if (userData) {
      const field = userData.querySelector(fieldName);
      if (field) {
        return field.textContent || undefined;
      }
    }

    // Try System section fields
    const system = doc.querySelector('System');
    if (system) {
      const field = system.querySelector(fieldName);
      if (field) {
        return field.textContent || field.getAttribute('SystemTime') || undefined;
      }
    }

    return undefined;
  } catch (e) {
    return undefined;
  }
}

/**
 * Get statistics about SIGMA detections
 */
export interface SigmaStats {
  totalRules: number;
  matchedRules: number;
  totalMatches: number;
  bySeverity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

export function getDetectionStats(
  matchesByRule: Map<string, SigmaMatch[]>
): SigmaStats {
  const stats: SigmaStats = {
    totalRules: matchesByRule.size,
    matchedRules: 0,
    totalMatches: 0,
    bySeverity: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    }
  };

  for (const [, matches] of matchesByRule.entries()) {
    if (matches.length > 0) {
      stats.matchedRules++;
      stats.totalMatches += matches.length;

      const severity = matches[0].rule.severity;
      stats.bySeverity[severity] += matches.length;
    }
  }

  return stats;
}
