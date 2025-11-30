/**
 * Auto-load SIGMA rules from bundled category files
 *
 * Loads pre-bundled rule files from /public/sigma-rules/
 * This eliminates the need for import.meta.glob and reduces bundle size
 */

import { SigmaEngine } from '../SigmaEngine';

/**
 * Supported SIGMA rule platforms
 * Only Windows is supported for EVTX file analysis
 */
export type SigmaPlatform = 'windows' | 'chainsaw';

/**
 * Platform metadata for UI display
 */
export interface PlatformInfo {
  id: SigmaPlatform;
  name: string;
  description: string;
  icon: string;
  ruleCount: number;
}

/**
 * Manifest entry for a rule category
 */
interface CategoryManifest {
  file: string;
  ruleCount: number;
  sizeBytes: number;
}

/**
 * Rule file entry
 */
interface RuleFile {
  path: string;
  content: string;
}

/**
 * Cached manifest to avoid repeated fetches
 */
let cachedManifest: Record<string, CategoryManifest> | null = null;

/**
 * Fetch and cache the manifest
 */
async function getManifest(): Promise<Record<string, CategoryManifest>> {
  if (cachedManifest) {
    return cachedManifest;
  }

  try {
    const response = await fetch('/sigma-rules/manifest.json');
    if (!response.ok) {
      throw new Error(`Failed to fetch manifest: ${response.statusText}`);
    }
    const manifest = await response.json();
    cachedManifest = manifest;
    return manifest;
  } catch (error) {
    return {};
  }
}

/**
 * Get available platforms with rule counts
 * Only returns Windows platform for EVTX compatibility
 */
export function getAvailablePlatforms(): PlatformInfo[] {
  // Return static info - actual counts will be loaded from manifest at runtime
  return [
    {
      id: 'windows',
      name: 'Windows - Official SIGMA',
      description: 'Windows Event Logs (EVTX), Sysmon, PowerShell, Security events',
      icon: '💠',
      ruleCount: 2349 // Total from build script
    },
    {
      id: 'chainsaw',
      name: 'Chainsaw',
      description: 'Windows-focused threat hunting rules (TAU format - coming soon)',
      icon: '🪚',
      ruleCount: 0 // Will be available when TAU engine is implemented
    }
  ];
}

/**
 * Load SIGMA rules for Windows platform from bundled category files
 */
export async function autoLoadRules(
  engine: SigmaEngine,
  _platform: SigmaPlatform = 'windows',
  onProgress?: (loaded: number, total: number) => void,
  categories?: string[]
): Promise<{
  loaded: number;
  failed: number;
  errors: string[];
}> {
  const result = {
    loaded: 0,
    failed: 0,
    errors: [] as string[]
  };

  try {
    // Load manifest to know which categories exist
    const manifest = await getManifest();

    // Determine which categories to load
    let categoriesToLoad = Object.keys(manifest);
    if (categories && categories.length > 0) {
      categoriesToLoad = categoriesToLoad.filter(cat => categories.includes(cat));
    }

    if (categoriesToLoad.length === 0) {
      result.errors.push('No matching categories found');
      return result;
    }

    const totalCategories = categoriesToLoad.length;
    let processedCategories = 0;

    // Load each category bundle
    for (const category of categoriesToLoad) {
      const categoryInfo = manifest[category];
      if (!categoryInfo) continue;

      try {
        // Fetch category bundle
        const response = await fetch(`/sigma-rules/${categoryInfo.file}`);
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const rules: RuleFile[] = await response.json();

        // Load each rule in the category
        for (const rule of rules) {
          try {
            const ruleIds = await engine.loadRules(rule.content);
            if (ruleIds.length > 0) {
              result.loaded += ruleIds.length;
            } else {
              result.failed++;
              result.errors.push(`${rule.path}: No valid rules found`);
            }
          } catch (error) {
            result.failed++;
            const errorMsg = error instanceof Error ? error.message : String(error);
            result.errors.push(`${rule.path}: ${errorMsg}`);
          }
        }

        processedCategories++;
        if (onProgress) {
          onProgress(processedCategories, totalCategories);
        }
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : String(error);
        result.errors.push(`Failed to load category ${category}: ${errorMsg}`);
        processedCategories++;
        if (onProgress) {
          onProgress(processedCategories, totalCategories);
        }
      }
    }
  } catch (error) {
    result.errors.push(`Auto-load failed: ${error instanceof Error ? error.message : String(error)}`);
  }

  return result;
}

/**
 * Get list of available categories for Windows platform
 */
export async function getAvailableCategories(_platform: SigmaPlatform = 'windows'): Promise<string[]> {
  const manifest = await getManifest();
  return Object.keys(manifest);
}

/**
 * Get list of available rule files for Windows platform
 * Note: This now returns category names since rules are bundled
 */
export function getAvailableRuleFiles(_platform: SigmaPlatform = 'windows'): string[] {
  // Return empty array since we're using bundled approach
  // Individual file paths are no longer relevant
  return [];
}
