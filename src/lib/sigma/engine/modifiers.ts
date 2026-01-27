/**
 * SIGMA Field Modifiers
 *
 * Implements all SIGMA field modification operators
 */

import { SigmaModifier } from '../types';

// ============================================================================
// REGEX MEMOIZATION CACHE
// ============================================================================

// Regex compilation cache - avoids recompiling the same patterns repeatedly
const regexCache = new Map<string, RegExp | null>();
const MAX_REGEX_CACHE_SIZE = 1000;

/**
 * Get or create a cached RegExp
 * Returns null if pattern is invalid or dangerous
 */
function getCachedRegex(pattern: string): RegExp | null {
  // Check cache first
  if (regexCache.has(pattern)) {
    return regexCache.get(pattern)!;
  }

  // Validate pattern length
  if (pattern.length > 500) {
    regexCache.set(pattern, null);
    return null;
  }

  // Check for dangerous patterns (nested quantifiers that could cause ReDoS)
  if (/(\+|\*|\{)\s*\1/.test(pattern) || /\([^)]*(\+|\*)[^)]*\)\s*(\+|\*)/.test(pattern)) {
    regexCache.set(pattern, null);
    return null;
  }

  // Compile regex
  try {
    const regex = new RegExp(pattern, 'i');

    // Evict oldest entry if cache is too large (LRU-like behavior)
    if (regexCache.size >= MAX_REGEX_CACHE_SIZE) {
      const firstKey = regexCache.keys().next().value;
      if (firstKey) regexCache.delete(firstKey);
    }

    regexCache.set(pattern, regex);
    return regex;
  } catch (e) {
    regexCache.set(pattern, null);
    return null;
  }
}

/**
 * Clear the regex cache (useful for testing or memory management)
 */
export function clearRegexCache(): void {
  regexCache.clear();
}

/**
 * Get regex cache stats for debugging
 */
export function getRegexCacheStats(): { size: number; maxSize: number } {
  return { size: regexCache.size, maxSize: MAX_REGEX_CACHE_SIZE };
}

// ============================================================================
// MODIFIER APPLICATION
// ============================================================================

/**
 * Apply modifier to field value and check if it matches target
 */
export function applyModifier(
  fieldValue: any,
  targetValue: any,
  modifier?: SigmaModifier
): boolean {
  // Handle undefined/null fields
  if (fieldValue === undefined || fieldValue === null) {
    // The 'exists' modifier explicitly checks for field existence
    return modifier === 'exists' ? false : false;
  }

  // Treat '?' as undefined (Sysmon uses '?' for unavailable metadata)
  // This prevents false positives when metadata fields are missing
  const fieldStr = String(fieldValue);
  if (fieldStr === '?') {
    return modifier === 'exists' ? false : false;
  }

  const targetStr = String(targetValue);
  const fieldLower = fieldStr.toLowerCase();
  const targetLower = typeof targetValue === 'string'
    ? targetStr === targetStr.toLowerCase() ? targetStr : targetStr.toLowerCase()
    : targetStr;

  switch (modifier) {
    case 'contains':
      return fieldLower.includes(targetLower);

    case 'startswith':
      return fieldLower.startsWith(targetLower);

    case 'endswith':
      return fieldLower.endsWith(targetLower);

    case 'all':
      // Value must contain all target values
      if (!Array.isArray(targetValue)) {
        return fieldLower.includes(targetLower);
      }
      return targetValue.every(v =>
        fieldLower.includes(String(v).toLowerCase())
      );

    case 're': {
      // Regular expression matching with memoized compilation
      const regex = getCachedRegex(targetStr);
      if (!regex) return false;
      return regex.test(fieldStr);
    }

    case 'base64':
      // Decode base64 and check
      try {
        const decoded = atob(fieldStr);
        return decoded.toLowerCase().includes(targetStr.toLowerCase());
      } catch (e) {
        return false;
      }

    case 'base64offset':
      // Base64 with offset variants (3 possible encodings)
      return checkBase64Offset(fieldStr, targetStr);

    case 'utf16le':
      // UTF-16 Little Endian encoding
      return checkUtf16(fieldStr, targetStr, 'le');

    case 'utf16be':
      // UTF-16 Big Endian encoding
      return checkUtf16(fieldStr, targetStr, 'be');

    case 'wide':
      // Wide character (null-byte separated)
      return checkWideChar(fieldStr, targetStr);

    case 'cidr':
      // CIDR notation matching for IP addresses
      return matchCIDR(fieldStr, targetValue);

    case 'exists':
      // Field exists (any non-null value)
      return true;

    default:
      // No modifier = exact match (case-insensitive)
      return fieldLower === targetLower;
  }
}

/**
 * Parse field name and extract modifier
 * e.g., "CommandLine|contains" => { field: "CommandLine", modifier: "contains" }
 * e.g., "CommandLine|contains|all" => { field: "CommandLine", modifier: "contains", requireAll: true }
 */
export function parseFieldModifier(fieldName: string): {
  field: string;
  modifier?: SigmaModifier;
  requireAll?: boolean;
} {
  const parts = fieldName.split('|');

  if (parts.length === 1) {
    return { field: parts[0] };
  }

  const field = parts[0];
  const modifiers = parts.slice(1).map(m => m.toLowerCase());

  // Validate modifier
  const validModifiers: SigmaModifier[] = [
    'contains',
    'startswith',
    'endswith',
    'all',
    're',
    'base64',
    'base64offset',
    'utf16le',
    'utf16be',
    'wide',
    'cidr',
    'exists'
  ];

  // Check for 'all' modifier (special case - it modifies behavior)
  const hasAll = modifiers.includes('all');
  const primaryModifier = modifiers.find(m => m !== 'all');

  if (!primaryModifier) {
    // Only 'all' modifier, treat as 'all'
    return { field, modifier: 'all' };
  }

  if (validModifiers.includes(primaryModifier as SigmaModifier)) {
    return {
      field,
      modifier: primaryModifier as SigmaModifier,
      requireAll: hasAll
    };
  }

  return { field: fieldName }; // Treat as field name if unknown modifier
}

/**
 * Check base64 with offset variants
 * Base64 encoding can have 3 different forms depending on offset
 */
function checkBase64Offset(fieldValue: string, target: string): boolean {
  try {
    // Try direct base64
    const decoded = atob(fieldValue);
    if (decoded.toLowerCase().includes(target.toLowerCase())) {
      return true;
    }

    // Try with offset padding
    for (const padding of ['A', 'AA', 'AAA']) {
      try {
        const paddedDecoded = atob(padding + fieldValue);
        if (paddedDecoded.toLowerCase().includes(target.toLowerCase())) {
          return true;
        }
      } catch (e) {
        // Ignore invalid padding
      }
    }

    return false;
  } catch (e) {
    return false;
  }
}

/**
 * Check UTF-16 encoded strings
 */
function checkUtf16(fieldValue: string, target: string, endian: 'le' | 'be'): boolean {
  try {
    // Convert target to UTF-16 pattern
    const utf16Pattern = target
      .split('')
      .map(c => {
        const code = c.charCodeAt(0);
        if (endian === 'le') {
          return String.fromCharCode(code & 0xff) + String.fromCharCode((code >> 8) & 0xff);
        } else {
          return String.fromCharCode((code >> 8) & 0xff) + String.fromCharCode(code & 0xff);
        }
      })
      .join('');

    return fieldValue.includes(utf16Pattern);
  } catch (e) {
    return false;
  }
}

/**
 * Check wide character encoding (null-byte separated)
 * e.g., "test" becomes "t\0e\0s\0t\0"
 */
function checkWideChar(fieldValue: string, target: string): boolean {
  const wideTarget = target.split('').join('\0') + '\0';
  return fieldValue.includes(wideTarget);
}

/**
 * Match IP address against CIDR notation
 * Supports both IPv4 and IPv6 CIDR ranges
 * Can match against single CIDR string or array of CIDR strings
 */
function matchCIDR(ipAddress: string, cidrValue: any): boolean {
  // Handle array of CIDR ranges
  if (Array.isArray(cidrValue)) {
    return cidrValue.some(cidr => matchSingleCIDR(ipAddress, String(cidr)));
  }

  // Handle single CIDR range
  return matchSingleCIDR(ipAddress, String(cidrValue));
}

/**
 * Match IP address against single CIDR notation
 */
function matchSingleCIDR(ipAddress: string, cidr: string): boolean {
  // Trim whitespace
  ipAddress = ipAddress.trim();
  cidr = cidr.trim();

  // Skip invalid/empty values
  if (!ipAddress || ipAddress === '-' || !cidr) {
    return false;
  }

  // Detect IPv6 vs IPv4 by presence of colon
  if (ipAddress.includes(':') || cidr.includes(':')) {
    return matchIPv6CIDR(ipAddress, cidr);
  } else {
    return matchIPv4CIDR(ipAddress, cidr);
  }
}

/**
 * Match IPv4 address against CIDR notation
 * e.g., "192.168.1.1" matches "192.168.0.0/16"
 */
function matchIPv4CIDR(ip: string, cidr: string): boolean {
  try {
    // Parse CIDR notation
    const [network, prefixStr] = cidr.split('/');
    const prefix = parseInt(prefixStr, 10);

    if (isNaN(prefix) || prefix < 0 || prefix > 32) {
      return false;
    }

    // Convert IP addresses to 32-bit integers
    const ipInt = ipv4ToInt(ip);
    const networkInt = ipv4ToInt(network);

    if (ipInt === null || networkInt === null) {
      return false;
    }

    // Create netmask
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;

    // Check if IP is in network range
    return (ipInt & mask) === (networkInt & mask);
  } catch (e) {
    return false;
  }
}

/**
 * Convert IPv4 address string to 32-bit integer
 */
function ipv4ToInt(ip: string): number | null {
  try {
    const parts = ip.split('.').map(p => parseInt(p, 10));

    if (parts.length !== 4) {
      return null;
    }

    if (parts.some(p => isNaN(p) || p < 0 || p > 255)) {
      return null;
    }

    return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
  } catch (e) {
    return null;
  }
}

/**
 * Match IPv6 address against CIDR notation
 * e.g., "fe80::1" matches "fe80::/10"
 */
function matchIPv6CIDR(ip: string, cidr: string): boolean {
  try {
    // Parse CIDR notation
    const [network, prefixStr] = cidr.split('/');
    const prefix = parseInt(prefixStr, 10);

    if (isNaN(prefix) || prefix < 0 || prefix > 128) {
      return false;
    }

    // Expand both addresses to full form
    const ipExpanded = expandIPv6(ip);
    const networkExpanded = expandIPv6(network);

    if (!ipExpanded || !networkExpanded) {
      return false;
    }

    // Convert to arrays of 16-bit segments
    const ipSegments = ipv6ToSegments(ipExpanded);
    const networkSegments = ipv6ToSegments(networkExpanded);

    if (!ipSegments || !networkSegments) {
      return false;
    }

    // Compare segments based on prefix length
    let bitsRemaining = prefix;
    for (let i = 0; i < 8 && bitsRemaining > 0; i++) {
      const bitsToCheck = Math.min(16, bitsRemaining);
      const mask = (0xffff << (16 - bitsToCheck)) & 0xffff;

      if ((ipSegments[i] & mask) !== (networkSegments[i] & mask)) {
        return false;
      }

      bitsRemaining -= bitsToCheck;
    }

    return true;
  } catch (e) {
    return false;
  }
}

/**
 * Expand IPv6 address to full form (no :: notation)
 */
function expandIPv6(ip: string): string | null {
  try {
    // Handle IPv4-mapped IPv6 addresses (e.g., ::ffff:192.168.1.1)
    if (ip.includes('.')) {
      const parts = ip.split(':');
      const ipv4Part = parts[parts.length - 1];
      const ipv4Segments = ipv4Part.split('.');

      if (ipv4Segments.length === 4) {
        // Convert IPv4 to hex segments
        const hex1 = (parseInt(ipv4Segments[0]) << 8 | parseInt(ipv4Segments[1])).toString(16).padStart(4, '0');
        const hex2 = (parseInt(ipv4Segments[2]) << 8 | parseInt(ipv4Segments[3])).toString(16).padStart(4, '0');
        ip = parts.slice(0, -1).join(':') + ':' + hex1 + ':' + hex2;
      }
    }

    // Split by '::'
    const parts = ip.split('::');

    if (parts.length > 2) {
      return null; // Invalid: multiple '::'
    }

    let segments: string[];

    if (parts.length === 2) {
      // Expand '::' notation
      const leftSegments = parts[0] ? parts[0].split(':') : [];
      const rightSegments = parts[1] ? parts[1].split(':') : [];
      const missingSegments = 8 - leftSegments.length - rightSegments.length;

      if (missingSegments < 0) {
        return null;
      }

      const zeroSegments = Array(missingSegments).fill('0');
      segments = [...leftSegments, ...zeroSegments, ...rightSegments];
    } else {
      // Already fully expanded
      segments = parts[0].split(':');
    }

    if (segments.length !== 8) {
      return null;
    }

    // Pad each segment to 4 hex digits
    return segments.map(s => s.padStart(4, '0')).join(':');
  } catch (e) {
    return null;
  }
}

/**
 * Convert expanded IPv6 address to array of 16-bit integer segments
 */
function ipv6ToSegments(expandedIp: string): number[] | null {
  try {
    const segments = expandedIp.split(':');

    if (segments.length !== 8) {
      return null;
    }

    return segments.map(s => parseInt(s, 16));
  } catch (e) {
    return null;
  }
}

/**
 * Get all possible field names from a field specification
 * Handles modifiers and returns base field name
 */
export function getBaseFieldName(fieldSpec: string): string {
  return parseFieldModifier(fieldSpec).field;
}

/**
 * Check if value matches with any of multiple patterns
 */
export function matchAny(
  fieldValue: any,
  patterns: any[],
  modifier?: SigmaModifier
): boolean {
  return patterns.some(pattern => applyModifier(fieldValue, pattern, modifier));
}

/**
 * Check if value matches with all patterns
 */
export function matchAll(
  fieldValue: any,
  patterns: any[],
  modifier?: SigmaModifier
): boolean {
  return patterns.every(pattern => applyModifier(fieldValue, pattern, modifier));
}

/**
 * Validate modifier is supported
 */
export function isValidModifier(modifier: string): boolean {
  const validModifiers: SigmaModifier[] = [
    'contains',
    'startswith',
    'endswith',
    'all',
    're',
    'base64',
    'base64offset',
    'utf16le',
    'utf16be',
    'wide',
    'cidr',
    'exists'
  ];

  return validModifiers.includes(modifier as SigmaModifier);
}
