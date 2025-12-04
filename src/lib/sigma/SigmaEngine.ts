/**
 * SIGMA Detection Engine
 *
 * Main engine class that provides a high-level API for SIGMA detection
 */

import { SigmaRule, CompiledSigmaRule, SigmaRuleMatch, SigmaEngineStats, SigmaConfig, SigmaLogSource } from './types';
import { parseSigmaRule, parseSigmaRules, validateSigmaRule } from './parser/yamlParser';
import { compileRule } from './engine/compiler';
import { matchAllEventsOptimized, matchRule } from './engine/matcher';
import { isWindowsCompatibleRule } from './engine/optimizedMatcher';

/**
 * Lazy-compiled rule storage
 */
interface LazyRule {
  rule: SigmaRule;
  compiled?: CompiledSigmaRule;
  isCompiled: boolean;
}

/**
 * SIGMA Detection Engine
 */
export class SigmaEngine {
  private rules: Map<string, CompiledSigmaRule> = new Map();
  private lazyRules: Map<string, LazyRule> = new Map();  // Uncompiled rules for lazy compilation
  private config: SigmaConfig;
  private stats: SigmaEngineStats = {
    rulesLoaded: 0,
    rulesCompiled: 0,
    eventsProcessed: 0,
    matchesFound: 0,
    averageMatchTime: 0,
    totalProcessingTime: 0
  };

  constructor(config: Partial<SigmaConfig> = {}) {
    this.config = {
      autoCompile: true,
      strictValidation: false,
      enableIndexing: false,
      maxRules: 1000,
      maxConditionDepth: 10,
      enableRegex: true,
      maxRegexLength: 500,
      regexTimeout: 1000,
      normalizeFields: true,
      ...config
    };
  }

  /**
   * Load a SIGMA rule from YAML string
   */
  async loadRule(yamlContent: string): Promise<string> {
    const rule = parseSigmaRule(yamlContent);

    // Validate rule
    if (this.config.strictValidation) {
      const validation = validateSigmaRule(rule);
      if (!validation.valid) {
        throw new Error(`Invalid rule: ${validation.errors.map(e => e.message).join(', ')}`);
      }
    }

    // Compile rule
    const compiled = compileRule(rule);

    // Store rule
    this.rules.set(rule.id, compiled);
    this.stats.rulesLoaded++;
    this.stats.rulesCompiled++;

    return rule.id;
  }

  /**
   * Load multiple SIGMA rules from YAML string
   */
  async loadRules(yamlContent: string): Promise<string[]> {
    const rules = parseSigmaRules(yamlContent);
    const ids: string[] = [];

    for (const rule of rules) {
      // Validate rule
      if (this.config.strictValidation) {
        const validation = validateSigmaRule(rule);
        if (!validation.valid) {
          continue;
        }
      }

      // Compile rule
      const compiled = compileRule(rule);

      // Store rule
      this.rules.set(rule.id, compiled);
      this.stats.rulesLoaded++;
      this.stats.rulesCompiled++;
      ids.push(rule.id);
    }

    return ids;
  }

  /**
   * Add a pre-compiled rule
   */
  addRule(rule: SigmaRule): string {
    const compiled = compileRule(rule);
    this.rules.set(rule.id, compiled);
    this.stats.rulesLoaded++;
    this.stats.rulesCompiled++;
    return rule.id;
  }

  /**
   * Remove a rule
   */
  removeRule(ruleId: string): boolean {
    const deleted = this.rules.delete(ruleId);
    if (deleted) {
      this.stats.rulesLoaded--;
      this.stats.rulesCompiled--;
    }
    return deleted;
  }

  /**
   * Get a rule by ID
   */
  getRule(ruleId: string): CompiledSigmaRule | undefined {
    return this.rules.get(ruleId);
  }

  /**
   * Get all rules
   */
  getAllRules(): CompiledSigmaRule[] {
    return Array.from(this.rules.values());
  }

  /**
   * Match events against all loaded rules
   * Uses optimized field indexing for better performance on large datasets
   */
  matchAll(events: any[]): Map<string, SigmaRuleMatch[]> {
    const startTime = performance.now();

    const compiledRules = Array.from(this.rules.values());
    const matches = matchAllEventsOptimized(events, compiledRules);

    const endTime = performance.now();
    const processingTime = endTime - startTime;

    // Update stats
    this.stats.eventsProcessed += events.length;
    this.stats.totalProcessingTime += processingTime;
    this.stats.averageMatchTime = this.stats.totalProcessingTime / this.stats.eventsProcessed;

    let totalMatches = 0;
    for (const ruleMatches of matches.values()) {
      totalMatches += ruleMatches.length;
    }
    this.stats.matchesFound += totalMatches;

    return matches;
  }

  /**
   * Match a single event against a compiled rule
   * Used for chunked processing to keep UI responsive
   */
  matchSingleEvent(event: any, compiledRule: CompiledSigmaRule): SigmaRuleMatch | null {
    return matchRule(event, compiledRule);
  }

  /**
   * Get engine statistics
   */
  getStats(): SigmaEngineStats {
    return { ...this.stats };
  }

  /**
   * Reset statistics
   */
  resetStats(): void {
    this.stats = {
      rulesLoaded: this.rules.size,
      rulesCompiled: this.rules.size,
      eventsProcessed: 0,
      matchesFound: 0,
      averageMatchTime: 0,
      totalProcessingTime: 0
    };
  }

  /**
   * Clear all rules
   */
  clearRules(): void {
    this.rules.clear();
    this.stats.rulesLoaded = 0;
    this.stats.rulesCompiled = 0;
  }

  /**
   * Get configuration
   */
  getConfig(): SigmaConfig {
    return { ...this.config };
  }

  // ============================================================================
  // LAZY COMPILATION METHODS
  // ============================================================================

  /**
   * Load a rule for lazy compilation (parse but don't compile)
   * Use this for bulk loading to defer compilation until needed
   */
  loadRuleLazy(yamlContent: string): string {
    const rule = parseSigmaRule(yamlContent);

    // Validate rule
    if (this.config.strictValidation) {
      const validation = validateSigmaRule(rule);
      if (!validation.valid) {
        throw new Error(`Invalid rule: ${validation.errors.map(e => e.message).join(', ')}`);
      }
    }

    // Store as lazy rule (uncompiled)
    this.lazyRules.set(rule.id, {
      rule,
      isCompiled: false
    });
    this.stats.rulesLoaded++;

    return rule.id;
  }

  /**
   * Load multiple rules for lazy compilation
   */
  loadRulesLazy(yamlContent: string): string[] {
    const rules = parseSigmaRules(yamlContent);
    const ids: string[] = [];

    for (const rule of rules) {
      if (this.config.strictValidation) {
        const validation = validateSigmaRule(rule);
        if (!validation.valid) continue;
      }

      this.lazyRules.set(rule.id, {
        rule,
        isCompiled: false
      });
      this.stats.rulesLoaded++;
      ids.push(rule.id);
    }

    return ids;
  }

  /**
   * Add a parsed rule for lazy compilation
   */
  addRuleLazy(rule: SigmaRule): string {
    this.lazyRules.set(rule.id, {
      rule,
      isCompiled: false
    });
    this.stats.rulesLoaded++;
    return rule.id;
  }

  /**
   * Compile a lazy rule on-demand
   */
  private compileLazyRule(ruleId: string): CompiledSigmaRule | undefined {
    const lazyRule = this.lazyRules.get(ruleId);
    if (!lazyRule) return undefined;

    if (!lazyRule.isCompiled) {
      const compiled = compileRule(lazyRule.rule);
      lazyRule.compiled = compiled;
      lazyRule.isCompiled = true;
      this.rules.set(ruleId, compiled);
      this.stats.rulesCompiled++;
    }

    return lazyRule.compiled;
  }

  /**
   * Compile all lazy rules matching a specific logsource
   * Only compiles rules that haven't been compiled yet and match the logsource
   */
  compileRulesForLogsource(logsource: SigmaLogSource): CompiledSigmaRule[] {
    const compiled: CompiledSigmaRule[] = [];

    for (const [ruleId, lazyRule] of this.lazyRules) {
      // Skip already-compiled rules
      if (lazyRule.isCompiled) {
        if (lazyRule.compiled) {
          compiled.push(lazyRule.compiled);
        }
        continue;
      }

      // Check if rule's logsource matches
      const ruleLogsource = lazyRule.rule.logsource;

      // Match if product matches (or either is undefined)
      const productMatch = !logsource.product || !ruleLogsource.product ||
        logsource.product === ruleLogsource.product;

      // Match if service matches (or either is undefined)
      const serviceMatch = !logsource.service || !ruleLogsource.service ||
        logsource.service === ruleLogsource.service;

      // Match if category matches (or either is undefined)
      const categoryMatch = !logsource.category || !ruleLogsource.category ||
        logsource.category === ruleLogsource.category;

      if (productMatch && serviceMatch && categoryMatch) {
        const compiledRule = this.compileLazyRule(ruleId);
        if (compiledRule) {
          compiled.push(compiledRule);
        }
      }
    }

    return compiled;
  }

  /**
   * Compile all Windows-compatible lazy rules
   */
  compileWindowsRules(): CompiledSigmaRule[] {
    const compiled: CompiledSigmaRule[] = [];

    for (const [ruleId, lazyRule] of this.lazyRules) {
      // Skip non-Windows rules
      if (!isWindowsCompatibleRule(lazyRule.rule.logsource)) {
        continue;
      }

      // Compile if not already compiled
      if (!lazyRule.isCompiled) {
        const compiledRule = this.compileLazyRule(ruleId);
        if (compiledRule) {
          compiled.push(compiledRule);
        }
      } else if (lazyRule.compiled) {
        compiled.push(lazyRule.compiled);
      }
    }

    return compiled;
  }

  /**
   * Get count of lazy (uncompiled) rules
   */
  getLazyRuleCount(): number {
    let count = 0;
    for (const lazyRule of this.lazyRules.values()) {
      if (!lazyRule.isCompiled) count++;
    }
    return count;
  }

  /**
   * Get total rule count (compiled + lazy)
   */
  getTotalRuleCount(): number {
    return this.rules.size + this.getLazyRuleCount();
  }
}

/**
 * Create a SIGMA engine instance
 */
export function createSigmaEngine(config?: Partial<SigmaConfig>): SigmaEngine {
  return new SigmaEngine(config);
}

// Export default instance
export default SigmaEngine;
