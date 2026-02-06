/**
 * SIGMA Rule Compiler
 *
 * Compiles parsed SIGMA rules into optimized executable format
 */

import { SigmaRule, CompiledSigmaRule, CompiledSelection, CompiledFieldCondition, ConditionNode, SigmaModifier } from '../types';
import { parseCondition } from '../parser/conditionParser';
import { parseFieldModifier } from './modifiers';

/**
 * Compile a SIGMA rule for fast matching
 */
export function compileRule(rule: SigmaRule): CompiledSigmaRule {
  // Parse the condition string into AST
  const conditionStr = rule.detection.condition;
  if (typeof conditionStr !== 'string') {
    throw new Error('Detection condition must be a string');
  }

  const conditionAST = parseCondition(conditionStr);

  // Compile all selections
  const selections = new Map<string, CompiledSelection>();
  const indexedFields: string[] = [];
  const requiredFields: string[] = [];

  for (const [selectionName, selectionDef] of Object.entries(rule.detection)) {
    // Skip non-selection keys
    if (selectionName === 'condition' || selectionName === 'timeframe') {
      continue;
    }

    if (typeof selectionDef === 'string') {
      continue; // This is the condition string
    }

    const compiledSelection = compileSelection(selectionName, selectionDef);
    selections.set(selectionName, compiledSelection);

    // Track fields for indexing
    for (const condition of compiledSelection.conditions) {
      if (!indexedFields.includes(condition.field)) {
        indexedFields.push(condition.field);
      }
      if (!requiredFields.includes(condition.field)) {
        requiredFields.push(condition.field);
      }
    }
  }

  return {
    rule,
    selections,
    condition: conditionAST,
    indexedFields,
    requiredFields
  };
}

/**
 * Calculate evaluation cost for a condition (lower = faster)
 */
function getConditionCost(condition: CompiledFieldCondition): number {
  // Fast fields - direct property access or indexed
  const fastFields = ['EventID', 'Provider', 'Computer', 'Level'];

  // Medium fields - commonly indexed/cached
  const mediumFields = [
    'Image', 'OriginalFileName', 'ParentImage', 'ParentCommandLine', 'CommandLine',
    'TargetObject', 'TargetFilename', 'DestinationIp', 'DestinationHostname',
    'Hashes', 'Company', 'Description', 'Product'
  ];

  let cost = 0;

  // Field access cost
  if (fastFields.includes(condition.field)) {
    cost += 1; // Fastest - direct property
  } else if (mediumFields.includes(condition.field)) {
    cost += 5; // Medium - pre-indexed field
  } else {
    cost += 10; // Slower - requires XML parsing
  }

  // Modifier cost
  if (!condition.modifier) {
    cost += 1; // Exact match is fastest
  } else if (condition.modifier === 'endswith' || condition.modifier === 'startswith') {
    cost += 5; // Fast string ops
  } else if (condition.modifier === 'contains') {
    cost += 10; // Slower string search
  } else if (condition.modifier === 're') {
    cost += 50; // Regex is expensive
  } else if (condition.modifier === 'exists') {
    cost += 2; // Presence check is cheap
  } else {
    cost += 20; // Other modifiers (base64, etc.)
  }

  // Multiple values add cost
  cost += condition.values.length * 0.5;

  return cost;
}

/**
 * Optimize condition ordering - sort by evaluation cost (fail-fast)
 */
function optimizeConditionOrder(conditions: CompiledFieldCondition[]): CompiledFieldCondition[] {
  // Don't reorder if there's only one condition
  if (conditions.length <= 1) return conditions;

  // Sort by cost (ascending - cheapest first)
  return [...conditions].sort((a, b) => {
    return getConditionCost(a) - getConditionCost(b);
  });
}

/**
 * Pre-lowercase string values for case-insensitive matching
 */
function preprocessConditionValues(condition: CompiledFieldCondition): CompiledFieldCondition {
  // Only preprocess string values for case-insensitive modifiers
  if (condition.modifier && ['contains', 'startswith', 'endswith'].includes(condition.modifier)) {
    return {
      ...condition,
      values: condition.values.map(v =>
        typeof v === 'string' ? v.toLowerCase() : v
      )
    };
  }
  return condition;
}

/**
 * Detect wildcard patterns and convert to appropriate modifier
 * Converts SIGMA wildcards (*) to contains/startswith/endswith modifiers
 */
function processWildcards(value: string | number | null, currentModifier?: SigmaModifier): {
  value: string | number | null;
  modifier?: SigmaModifier;
} {
  // Skip if already has a modifier or if not a string
  if (currentModifier || typeof value !== 'string') {
    return { value, modifier: currentModifier };
  }

  const str = value as string;

  // Check for wildcards
  const startsWithWildcard = str.startsWith('*');
  const endsWithWildcard = str.endsWith('*');

  // No wildcards - use default exact matching
  if (!startsWithWildcard && !endsWithWildcard) {
    return { value, modifier: currentModifier };
  }

  // Both ends have wildcard: *something* -> contains
  if (startsWithWildcard && endsWithWildcard) {
    return {
      value: str.slice(1, -1), // Remove both * wildcards
      modifier: 'contains' as SigmaModifier
    };
  }

  // Only starts with wildcard: *something -> endswith
  if (startsWithWildcard) {
    return {
      value: str.slice(1), // Remove leading *
      modifier: 'endswith' as SigmaModifier
    };
  }

  // Only ends with wildcard: something* -> startswith
  if (endsWithWildcard) {
    return {
      value: str.slice(0, -1), // Remove trailing *
      modifier: 'startswith' as SigmaModifier
    };
  }

  return { value, modifier: currentModifier };
}

/**
 * Compile a selection into field conditions
 */
function compileSelection(name: string, selection: any): CompiledSelection {
  const conditions: CompiledFieldCondition[] = [];

  // Handle array-based selections (OR logic between items)
  if (Array.isArray(selection)) {
    // Each array item is a separate condition with OR logic
    // We compile them as separate conditions but mark them for OR evaluation
    for (const item of selection) {
      for (const [fieldSpec, value] of Object.entries(item)) {
        const { field, modifier, requireAll } = parseFieldModifier(fieldSpec);
        const values = Array.isArray(value) ? value : [value];

        // Process wildcards for each value
        const processedValues = values.map(v => {
          const result = processWildcards(v, modifier);
          return result.value;
        });

        // Get modifier from first wildcard-processed value (they should all have the same pattern)
        const detectedModifier = values.length > 0 ? processWildcards(values[0], modifier).modifier : modifier;

        conditions.push({
          field,
          modifier: detectedModifier,
          values: processedValues,
          negate: false,
          requireAll
        });
      }
    }
  } else {
    // Object-based selection (AND logic between keys)
    for (const [fieldSpec, value] of Object.entries(selection)) {
      // Parse field name and modifier
      const { field, modifier, requireAll } = parseFieldModifier(fieldSpec);

      // Normalize value to array
      const values = Array.isArray(value) ? value : [value];

      // Process wildcards for each value
      const processedValues = values.map(v => {
        const result = processWildcards(v, modifier);
        return result.value;
      });

      // Get modifier from first wildcard-processed value (they should all have the same pattern)
      const detectedModifier = values.length > 0 ? processWildcards(values[0], modifier).modifier : modifier;

      conditions.push({
        field,
        modifier: detectedModifier,
        values: processedValues,
        negate: false,
        requireAll
      });
    }
  }

  // OPTIMIZATION: Reorder conditions by evaluation cost (fail-fast)
  const optimizedConditions = optimizeConditionOrder(conditions);

  // OPTIMIZATION: Pre-lowercase string values for faster matching
  const preprocessedConditions = optimizedConditions.map(preprocessConditionValues);

  return {
    name,
    conditions: preprocessedConditions,
    useOrLogic: Array.isArray(selection),
    originalDefinition: selection
  };
}

/**
 * Compile multiple rules
 */
export function compileRules(rules: SigmaRule[]): CompiledSigmaRule[] {
  return rules.map(rule => compileRule(rule));
}

/**
 * Validate compiled rule
 */
export function validateCompiledRule(compiledRule: CompiledSigmaRule): {
  valid: boolean;
  errors: string[];
} {
  const errors: string[] = [];

  // Check that all referenced selections exist
  const availableSelections = Array.from(compiledRule.selections.keys());
  const referencedSelections = getReferencedSelections(compiledRule.condition);

  for (const ref of referencedSelections) {
    if (!ref.includes('*') && !availableSelections.includes(ref)) {
      errors.push(`Selection '${ref}' referenced in condition but not defined`);
    }
  }

  // Check for empty selections
  for (const [name, selection] of compiledRule.selections) {
    if (selection.conditions.length === 0) {
      errors.push(`Selection '${name}' has no conditions`);
    }
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Get all selection names referenced in condition AST
 */
function getReferencedSelections(node: ConditionNode): Set<string> {
  const selections = new Set<string>();

  function traverse(n: ConditionNode) {
    if (n.type === 'SELECTION' && n.value) {
      selections.add(String(n.value));
    } else if (n.type === 'COUNT' && n.value) {
      selections.add(String(n.value));
    } else if (n.type === 'ONE_OF' || n.type === 'ALL_OF') {
      if (n.pattern) {
        selections.add(n.pattern);
      }
    }

    if (n.children) {
      n.children.forEach(traverse);
    }
  }

  traverse(node);
  return selections;
}

/**
 * Optimize compiled rule for performance
 * - Reorder conditions (most selective first)
 * - Combine similar conditions
 * - Pre-compute regex patterns
 */
export function optimizeCompiledRule(compiledRule: CompiledSigmaRule): CompiledSigmaRule {
  // For now, return as-is
  // Future optimizations:
  // - Sort conditions by selectivity (EventID first, then Provider, then contains)
  // - Pre-compile regex patterns
  // - Combine multiple contains into single regex
  return compiledRule;
}

/**
 * Get rule metadata summary
 */
export function getRuleMetadata(compiledRule: CompiledSigmaRule): {
  id: string;
  title: string;
  level: string;
  selectionCount: number;
  fieldCount: number;
  requiredFields: string[];
} {
  return {
    id: compiledRule.rule.id,
    title: compiledRule.rule.title,
    level: compiledRule.rule.level || 'medium',
    selectionCount: compiledRule.selections.size,
    fieldCount: compiledRule.indexedFields?.length || 0,
    requiredFields: compiledRule.requiredFields || []
  };
}
