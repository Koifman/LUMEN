/**
 * Generate a consistent color for a filename
 * Uses a simple hash function to ensure the same file always gets the same color
 */
export function getFileColor(filename: string): string {
  if (!filename) return 'rgba(255, 255, 255, 0.1)';

  // Simple hash function
  let hash = 0;
  for (let i = 0; i < filename.length; i++) {
    hash = filename.charCodeAt(i) + ((hash << 5) - hash);
  }

  // Convert hash to hue (0-360)
  const hue = Math.abs(hash % 360);

  // Use HSL for better color distribution
  // Keep saturation and lightness moderate for readability
  return `hsl(${hue}, 60%, 50%)`;
}

/**
 * Get a lighter version of the file color for backgrounds
 */
export function getFileBgColor(filename: string): string {
  if (!filename) return 'rgba(255, 255, 255, 0.05)';

  let hash = 0;
  for (let i = 0; i < filename.length; i++) {
    hash = filename.charCodeAt(i) + ((hash << 5) - hash);
  }

  const hue = Math.abs(hash % 360);
  return `hsla(${hue}, 60%, 50%, 0.1)`;
}

/**
 * Get all colors for a list of files
 */
export function getFileColorMap(files: string[]): Map<string, { color: string; bgColor: string }> {
  const map = new Map<string, { color: string; bgColor: string }>();

  for (const file of files) {
    map.set(file, {
      color: getFileColor(file),
      bgColor: getFileBgColor(file)
    });
  }

  return map;
}
