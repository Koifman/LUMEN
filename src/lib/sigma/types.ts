/**
 * SIGMA Detection Engine - Type Definitions
 *
 * Comprehensive type definitions for full SIGMA specification support
 */

/**
 * SIGMA Rule Status
 */
export type SigmaStatus = 'experimental' | 'test' | 'stable' | 'deprecated';

/**
 * SIGMA Rule Level (Severity)
 */
export type SigmaLevel = 'critical' | 'high' | 'medium' | 'low' | 'informational';

/**
 * Log Source Definition
 */
export interface SigmaLogSource {
  product?: string;      // e.g., 'windows', 'linux'
  service?: string;      // e.g., 'sysmon', 'security'
  category?: string;     // e.g., 'process_creation', 'network_connection'
  definition?: string;   // Custom definition
}

/**
 * Field Modifiers
 */
export type SigmaModifier =
  | 'contains'
  | 'startswith'
  | 'endswith'
  | 'all'
  | 're'           // regex
  | 'base64'
  | 'base64offset'
  | 'utf16le'
  | 'utf16be'
  | 'wide'
  | 'exists';      // field exists (any value)

/**
 * Field Value - can be string, number, array, or null
 */
export type SigmaFieldValue = string | number | null | (string | number | null)[];

/**
 * Detection Selection - field conditions
 */
export interface SigmaSelection {
  [field: string]: SigmaFieldValue;
}

/**
 * Detection Block - named selections
 */
export interface SigmaDetection {
  [selectionName: string]: SigmaSelection | string; // string = condition
}

/**
 * Parsed Condition AST Node Types
 */
export type ConditionNodeType =
  | 'AND'
  | 'OR'
  | 'NOT'
  | 'SELECTION'    // Reference to a selection
  | 'ONE_OF'       // 1 of pattern*
  | 'ALL_OF'       // all of pattern*
  | 'COUNT';       // count(selection) > N

/**
 * Condition AST Node
 */
export interface ConditionNode {
  type: ConditionNodeType;
  value?: string | number;
  children?: ConditionNode[];
  pattern?: string;     // For pattern matching (e.g., "selection*")
  operator?: '>' | '<' | '>=' | '<=' | '=='; // For COUNT
  threshold?: number;   // For COUNT
}

/**
 * Full SIGMA Rule Structure
 */
export interface SigmaRule {
  // Metadata
  title: string;
  id: string;
  status?: SigmaStatus;
  description?: string;
  author?: string;
  date?: string;
  modified?: string;
  references?: string[];
  tags?: string[];
  falsepositives?: string[];
  level?: SigmaLevel;

  // Log Source
  logsource: SigmaLogSource;

  // Detection
  detection: SigmaDetection;

  // Parsed condition (compiled)
  _compiledCondition?: ConditionNode;

  // Original YAML (for debugging)
  _originalYaml?: string;
}

/**
 * Compiled Field Condition
 * Represents a single field match with modifiers
 */
export interface CompiledFieldCondition {
  field: string;
  modifier?: SigmaModifier;
  values: (string | number | null)[];
  negate?: boolean;
  requireAll?: boolean; // For contains|all, startswith|all, etc.
}

/**
 * Compiled Selection
 * Conditions can use AND logic (default) or OR logic (for array-based selections)
 */
export interface CompiledSelection {
  name: string;
  conditions: CompiledFieldCondition[];
  useOrLogic?: boolean; // True for array-based selections
  originalDefinition?: any; // Original YAML definition for tooltip display
}

/**
 * Compiled SIGMA Rule
 * Pre-processed for fast matching
 */
export interface CompiledSigmaRule {
  // Original rule metadata
  rule: SigmaRule;

  // Compiled selections
  selections: Map<string, CompiledSelection>;

  // Compiled condition tree
  condition: ConditionNode;

  // Performance hints
  indexedFields?: string[];  // Fields to index for fast lookup
  requiredFields?: string[]; // Fields that must exist
}

/**
 * Field Match Result
 */
export interface FieldMatchResult {
  field: string;
  value: any;
  matched: boolean;
  modifier?: SigmaModifier;
  matchedPattern?: string | number | null | (string | number | null)[]; // The specific pattern value(s) that caused the match
}

/**
 * Selection Match Result
 */
export interface SelectionMatchResult {
  selection: string;
  matched: boolean;
  fieldMatches: FieldMatchResult[];
}

/**
 * Rule Match Result
 */
export interface SigmaRuleMatch {
  rule: SigmaRule;
  matched: boolean;
  selectionMatches: SelectionMatchResult[];
  event: any; // The matched event
  timestamp: Date;
  compiledRule?: CompiledSigmaRule; // Include compiled rule for accessing selection definitions
}

/**
 * Engine Statistics
 */
export interface SigmaEngineStats {
  rulesLoaded: number;
  rulesCompiled: number;
  eventsProcessed: number;
  matchesFound: number;
  averageMatchTime: number; // milliseconds
  totalProcessingTime: number; // milliseconds
}

/**
 * Rule Validation Error
 */
export interface SigmaValidationError {
  field: string;
  message: string;
  severity: 'error' | 'warning';
}

/**
 * Rule Validation Result
 */
export interface SigmaValidationResult {
  valid: boolean;
  errors: SigmaValidationError[];
  warnings: SigmaValidationError[];
}

/**
 * SIGMA Configuration
 */
export interface SigmaConfig {
  // Rule loading
  autoCompile?: boolean;           // Auto-compile rules on load
  strictValidation?: boolean;      // Strict YAML validation

  // Performance
  enableIndexing?: boolean;        // Enable field indexing
  maxRules?: number;              // Max rules to load
  maxConditionDepth?: number;     // Max condition nesting

  // Regex
  enableRegex?: boolean;          // Enable regex support
  maxRegexLength?: number;        // Max regex pattern length
  regexTimeout?: number;          // Regex timeout (ms)

  // Field extraction
  fieldMappings?: Record<string, string>; // Custom field name mappings
  normalizeFields?: boolean;      // Normalize field names
}

/**
 * Event Field Extractor
 * Interface for custom field extraction from events
 */
export interface FieldExtractor {
  extract(event: any, fieldPath: string): any;
  exists(event: any, fieldPath: string): boolean;
}

/**
 * Rule Source
 * Where a rule came from
 */
export interface RuleSource {
  type: 'builtin' | 'file' | 'url' | 'custom';
  location?: string;
  loadedAt: Date;
}

/**
 * Rule Metadata
 * Extended metadata for rule management
 */
export interface RuleMetadata {
  source: RuleSource;
  enabled: boolean;
  compiled: boolean;
  lastMatched?: Date;
  matchCount: number;
}
