/**
 * SIGMA Condition Parser
 *
 * Parses detection conditions into executable AST
 * Supports: AND, OR, NOT, 1 of, all of, count()
 */

import { ConditionNode } from '../types';

/**
 * Parse SIGMA condition string into AST
 *
 * Examples:
 * - "selection"
 * - "selection1 and selection2"
 * - "selection1 or selection2"
 * - "selection and not filter"
 * - "1 of selection*"
 * - "all of selection*"
 * - "selection1 or (selection2 and selection3)"
 */
export function parseCondition(condition: string): ConditionNode {
  const tokens = tokenize(condition);
  const ast = parseExpression(tokens, 0);
  return ast.node;
}

interface ParseResult {
  node: ConditionNode;
  position: number;
}

/**
 * Tokenize condition string
 */
function tokenize(condition: string): string[] {
  // Normalize whitespace
  condition = condition.trim();

  const tokens: string[] = [];
  let current = '';

  for (let i = 0; i < condition.length; i++) {
    const char = condition[i];

    if (char === '(') {
      if (current.trim()) {
        tokens.push(current.trim());
        current = '';
      }
      tokens.push('(');
    } else if (char === ')') {
      if (current.trim()) {
        tokens.push(current.trim());
        current = '';
      }
      tokens.push(')');
    } else if (char === ' ') {
      if (current.trim()) {
        tokens.push(current.trim());
        current = '';
      }
    } else {
      current += char;
    }
  }

  if (current.trim()) {
    tokens.push(current.trim());
  }

  return tokens;
}

/**
 * Parse expression with operator precedence
 * Precedence: NOT > AND > OR
 */
function parseExpression(tokens: string[], start: number): ParseResult {
  return parseOr(tokens, start);
}

/**
 * Parse OR expression (lowest precedence)
 */
function parseOr(tokens: string[], start: number): ParseResult {
  let result = parseAnd(tokens, start);
  let pos = result.position;

  while (pos < tokens.length && tokens[pos]?.toLowerCase() === 'or') {
    pos++; // Skip 'or'
    const right = parseAnd(tokens, pos);

    result = {
      node: {
        type: 'OR',
        children: [result.node, right.node]
      },
      position: right.position
    };

    pos = right.position;
  }

  return result;
}

/**
 * Parse AND expression (medium precedence)
 */
function parseAnd(tokens: string[], start: number): ParseResult {
  let result = parseNot(tokens, start);
  let pos = result.position;

  while (pos < tokens.length && tokens[pos]?.toLowerCase() === 'and') {
    pos++; // Skip 'and'
    const right = parseNot(tokens, pos);

    result = {
      node: {
        type: 'AND',
        children: [result.node, right.node]
      },
      position: right.position
    };

    pos = right.position;
  }

  return result;
}

/**
 * Parse NOT expression (highest precedence)
 */
function parseNot(tokens: string[], start: number): ParseResult {
  if (tokens[start]?.toLowerCase() === 'not') {
    const inner = parsePrimary(tokens, start + 1);
    return {
      node: {
        type: 'NOT',
        children: [inner.node]
      },
      position: inner.position
    };
  }

  return parsePrimary(tokens, start);
}

/**
 * Parse primary expression (selection, pattern, count, parentheses)
 */
function parsePrimary(tokens: string[], start: number): ParseResult {
  const token = tokens[start];

  if (!token) {
    throw new Error('Unexpected end of condition');
  }

  // Parentheses
  if (token === '(') {
    const inner = parseExpression(tokens, start + 1);
    if (tokens[inner.position] !== ')') {
      throw new Error('Missing closing parenthesis');
    }
    return {
      node: inner.node,
      position: inner.position + 1
    };
  }

  // "1 of pattern*" or "all of pattern*"
  if (token.toLowerCase() === '1' || token.toLowerCase() === 'all') {
    return parsePatternMatch(tokens, start);
  }

  // "count(selection) > N"
  if (token.toLowerCase().startsWith('count(')) {
    return parseCount(tokens, start);
  }

  // Simple selection reference
  return {
    node: {
      type: 'SELECTION',
      value: token
    },
    position: start + 1
  };
}

/**
 * Parse pattern matching: "1 of selection*", "all of selection*"
 */
function parsePatternMatch(tokens: string[], start: number): ParseResult {
  const quantifier = tokens[start]?.toLowerCase(); // '1' or 'all'
  const of = tokens[start + 1]?.toLowerCase();
  const pattern = tokens[start + 2];

  if (of !== 'of') {
    throw new Error(`Expected 'of' after '${quantifier}', got '${of}'`);
  }

  if (!pattern) {
    throw new Error('Expected pattern after "of"');
  }

  return {
    node: {
      type: quantifier === '1' ? 'ONE_OF' : 'ALL_OF',
      pattern
    },
    position: start + 3
  };
}

/**
 * Parse count expression: "count(selection) > 5"
 */
function parseCount(tokens: string[], start: number): ParseResult {
  const countExpr = tokens[start];

  // Extract selection name from "count(selection)"
  const match = countExpr.match(/^count\(([^)]+)\)$/i);
  if (!match) {
    throw new Error(`Invalid count expression: ${countExpr}`);
  }

  const selection = match[1];
  const operator = tokens[start + 1];
  const threshold = tokens[start + 2];

  if (!operator || !threshold) {
    throw new Error('Count expression requires operator and threshold');
  }

  const validOps = ['>', '<', '>=', '<=', '=='];
  if (!validOps.includes(operator)) {
    throw new Error(`Invalid count operator: ${operator}`);
  }

  const thresholdNum = parseInt(threshold, 10);
  if (isNaN(thresholdNum)) {
    throw new Error(`Invalid count threshold: ${threshold}`);
  }

  return {
    node: {
      type: 'COUNT',
      value: selection,
      operator: operator as any,
      threshold: thresholdNum
    },
    position: start + 3
  };
}

/**
 * Get all selection names referenced in condition
 */
export function getReferencedSelections(condition: ConditionNode): Set<string> {
  const selections = new Set<string>();

  function traverse(node: ConditionNode) {
    if (node.type === 'SELECTION' && node.value) {
      selections.add(String(node.value));
    } else if (node.type === 'COUNT' && node.value) {
      selections.add(String(node.value));
    }

    if (node.children) {
      node.children.forEach(traverse);
    }
  }

  traverse(condition);
  return selections;
}

/**
 * Expand pattern references to actual selection names
 * e.g., "selection*" matches "selection1", "selection2", etc.
 */
export function expandPattern(pattern: string, availableSelections: string[]): string[] {
  if (!pattern.includes('*')) {
    return [pattern];
  }

  const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
  return availableSelections.filter(sel => regex.test(sel));
}

/**
 * Validate condition against available selections
 */
export function validateCondition(
  condition: ConditionNode,
  availableSelections: string[]
): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  const referencedSelections = getReferencedSelections(condition);

  for (const sel of referencedSelections) {
    if (!availableSelections.includes(sel)) {
      // Check if it's a pattern
      if (!sel.includes('*')) {
        errors.push(`Selection '${sel}' referenced in condition but not defined`);
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors
  };
}
