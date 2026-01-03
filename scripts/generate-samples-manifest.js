/**
 * Generate EVTX Samples Manifest
 *
 * Scans the EVTX-ATTACK-SAMPLES directory and generates a JSON manifest
 * listing all available samples organized by category.
 */

import { readdirSync, statSync, writeFileSync } from 'fs';
import { join, basename } from 'path';

const SAMPLES_DIR = 'samples/EVTX-ATTACK-SAMPLES';
const OUTPUT_FILE = 'public/samples-manifest.json';

// Categories to exclude (non-category directories)
const EXCLUDE_DIRS = new Set([
  'EVTX_ATT&CK_Metadata',
  '.git'
]);

// Files to exclude
const EXCLUDE_FILES = new Set([
  'README.md',
  'LICENSE.GPL',
  'evtx_data.csv',
  'AIEvent.jpg',
  'EVTX_DataSet_Stats.PNG',
  'HeatMap.PNG',
  'mitre_evtx_repo_map.png',
  'temp-plot.html',
  '.gitignore',
  '.DS_Store',
  'Thumbs.db',
  'desktop.ini'
]);

/**
 * Generate a human-readable name from filename
 */
function generateSampleName(filename) {
  // Remove .evtx extension
  let name = filename.replace(/\.evtx$/i, '');

  // Replace underscores with spaces
  name = name.replace(/_/g, ' ');

  // Capitalize each word
  name = name.split(' ').map(word => {
    // Keep acronyms uppercase (all caps words)
    if (word === word.toUpperCase() && word.length > 1) {
      return word;
    }
    // Capitalize first letter
    return word.charAt(0).toUpperCase() + word.slice(1).toLowerCase();
  }).join(' ');

  return name;
}

/**
 * Generate category description based on name
 */
function getCategoryDescription(categoryName) {
  const descriptions = {
    'Execution': 'Process execution and command line attacks',
    'Defense Evasion': 'Techniques to avoid detection',
    'Persistence': 'Techniques for maintaining access',
    'Privilege Escalation': 'Techniques to gain higher privileges',
    'Credential Access': 'Credential dumping and password attacks',
    'Discovery': 'System and network discovery techniques',
    'Lateral Movement': 'Moving through the network',
    'Command and Control': 'C2 communications and tunneling',
    'AutomatedTestingTools': 'Automated testing tool outputs',
    'Other': 'Miscellaneous attack samples'
  };

  return descriptions[categoryName] || `${categoryName} attack techniques`;
}

/**
 * Scan directory for EVTX samples
 */
function scanSamples() {
  const manifest = {
    categories: [],
    generatedAt: new Date().toISOString(),
    totalSamples: 0
  };

  try {
    const categories = readdirSync(SAMPLES_DIR);

    for (const categoryName of categories) {
      // Skip excluded directories and files
      if (EXCLUDE_DIRS.has(categoryName) || EXCLUDE_FILES.has(categoryName)) {
        continue;
      }

      const categoryPath = join(SAMPLES_DIR, categoryName);

      // Skip if not a directory
      if (!statSync(categoryPath).isDirectory()) {
        continue;
      }

      // Read samples in this category
      const files = readdirSync(categoryPath);
      const samples = [];

      for (const filename of files) {
        // Only include .evtx files
        if (!filename.toLowerCase().endsWith('.evtx')) {
          continue;
        }

        const filePath = join(categoryPath, filename);

        // Skip if not a file
        if (!statSync(filePath).isFile()) {
          continue;
        }

        samples.push({
          name: generateSampleName(filename),
          file: filename,
          category: categoryName
        });
      }

      // Only add category if it has samples
      if (samples.length > 0) {
        manifest.categories.push({
          name: categoryName,
          description: getCategoryDescription(categoryName),
          sampleCount: samples.length,
          samples: samples.sort((a, b) => a.name.localeCompare(b.name))
        });

        manifest.totalSamples += samples.length;
      }
    }

    // Sort categories by name
    manifest.categories.sort((a, b) => a.name.localeCompare(b.name));

  } catch (error) {
    console.error(`Error scanning samples directory: ${error.message}`);
    process.exit(1);
  }

  return manifest;
}

/**
 * Main execution
 */
function main() {
  console.log('📦 Generating EVTX samples manifest...\n');

  const manifest = scanSamples();

  // Write manifest
  writeFileSync(OUTPUT_FILE, JSON.stringify(manifest, null, 2));

  console.log(`✅ Generated manifest with ${manifest.categories.length} categories`);
  console.log(`📊 Total samples: ${manifest.totalSamples}`);
  console.log(`📝 Manifest written to: ${OUTPUT_FILE}\n`);

  // Print summary
  manifest.categories.forEach(cat => {
    console.log(`   ${cat.name.padEnd(30)} ${cat.sampleCount.toString().padStart(3)} samples`);
  });
}

main();
