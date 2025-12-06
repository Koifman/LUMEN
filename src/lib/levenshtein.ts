/**
 * Calculates the Levenshtein distance between two strings with optimizations
 *
 * The Levenshtein distance is a string metric for measuring the difference between
 * two sequences. It is the minimum number of single-character edits (insertions,
 * deletions, or substitutions) required to change one string into the other.
 *
 * Optimizations:
 * - Uses O(min(m,n)) space instead of O(m*n) by using rolling arrays
 * - Early termination when threshold is exceeded
 * - Assumes strings are already lowercase (for performance)
 *
 * @param str1 - First string to compare (assumed lowercase)
 * @param str2 - Second string to compare (assumed lowercase)
 * @param threshold - Optional max distance to consider (returns early if exceeded)
 * @returns The Levenshtein distance (number of edits needed), or threshold+1 if exceeded
 *
 * @example
 * levenshteinDistance('svchost.exe', 'svch0st.exe') // Returns 1
 * levenshteinDistance('chrome.exe', 'chromee.exe')  // Returns 1
 * levenshteinDistance('lsass.exe', 'lsas.exe')      // Returns 1
 */
export function levenshteinDistance(
  str1: string,
  str2: string,
  threshold: number = Infinity
): number {
  const s1 = str1;
  const s2 = str2;

  const len1 = s1.length;
  const len2 = s2.length;

  // Early termination: if length difference exceeds threshold, distance must exceed threshold
  if (Math.abs(len1 - len2) > threshold) {
    return threshold + 1;
  }

  // Handle edge cases
  if (len1 === 0) return len2;
  if (len2 === 0) return len1;

  // Ensure s1 is the shorter string (optimization)
  if (len1 > len2) {
    return levenshteinDistance(s2, s1, threshold);
  }

  // Use two rows instead of full matrix (space optimization)
  let prevRow = new Array(len1 + 1);
  let currRow = new Array(len1 + 1);

  // Initialize first row
  for (let i = 0; i <= len1; i++) {
    prevRow[i] = i;
  }

  // Fill in the rest
  for (let j = 1; j <= len2; j++) {
    currRow[0] = j;
    let minDistanceInRow = j; // Track minimum in current row for early termination

    for (let i = 1; i <= len1; i++) {
      const cost = s1[i - 1] === s2[j - 1] ? 0 : 1;

      currRow[i] = Math.min(
        prevRow[i] + 1,      // deletion
        currRow[i - 1] + 1,  // insertion
        prevRow[i - 1] + cost // substitution
      );

      if (currRow[i] < minDistanceInRow) {
        minDistanceInRow = currRow[i];
      }
    }

    // Early termination: if all values in current row exceed threshold, we can stop
    if (minDistanceInRow > threshold) {
      return threshold + 1;
    }

    // Swap rows
    const temp = prevRow;
    prevRow = currRow;
    currRow = temp;
  }

  return prevRow[len1];
}

/**
 * Finds the closest match from a list of legitimate processes (optimized)
 *
 * Optimizations:
 * - Pre-normalizes process name once
 * - Passes threshold to levenshteinDistance for early termination
 * - Pre-filters by length difference before expensive calculation
 * - Assumes legitimateProcesses array contains lowercase strings
 *
 * @param processName - The process name to check
 * @param legitimateProcesses - Array of known legitimate process names (assumed lowercase)
 * @param threshold - Maximum Levenshtein distance to consider a match
 * @returns Object with the closest match and its distance, or null if no match within threshold
 */
export function findClosestMatch(
  processName: string,
  legitimateProcesses: string[],
  threshold: number = 3
): { match: string; distance: number } | null {
  let closestMatch: string | null = null;
  let minDistance = threshold + 1; // Start with threshold+1, only update if we find something closer

  const normalizedProcessName = processName.toLowerCase();
  const processLength = normalizedProcessName.length;

  for (const legitimate of legitimateProcesses) {
    // Quick pre-filter: if length difference exceeds threshold, skip
    const lengthDiff = Math.abs(processLength - legitimate.length);
    if (lengthDiff > threshold) {
      continue;
    }

    // Calculate distance with early termination at current minDistance
    const distance = levenshteinDistance(
      normalizedProcessName,
      legitimate,
      Math.min(threshold, minDistance - 1)
    );

    // Only consider matches within the threshold, non-exact (distance > 0), and closer than previous
    if (distance > 0 && distance <= threshold && distance < minDistance) {
      minDistance = distance;
      closestMatch = legitimate;

      // Early exit if we find distance of 1 (can't get closer while excluding exact matches)
      if (minDistance === 1) {
        break;
      }
    }
  }

  return closestMatch ? { match: closestMatch, distance: minDistance } : null;
}
