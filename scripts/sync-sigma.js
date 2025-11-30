#!/usr/bin/env node

/**
 * Sync SIGMA and Chainsaw detection rules from upstream repositories
 *
 * This script updates the Git submodules to pull the latest detection rules
 * from SigmaHQ and Chainsaw before bundling them for use in LUMEN.
 */

import { execSync } from 'child_process';
import { existsSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = join(__dirname, '..');

console.log('🔄 Syncing detection rules from upstream repositories...\n');

// Check if running in a Git repository
try {
  execSync('git rev-parse --git-dir', {
    cwd: projectRoot,
    stdio: 'ignore'
  });
} catch (error) {
  console.error('❌ Not a Git repository. Skipping submodule sync.');
  process.exit(0);
}

// Check if submodules are initialized
const sigmaPath = join(projectRoot, 'src', 'sigma-master');
const chainsawPath = join(projectRoot, 'src', 'chainsaw-rules');

const sigmaExists = existsSync(join(sigmaPath, '.git'));
const chainsawExists = existsSync(join(chainsawPath, '.git'));

if (!sigmaExists && !chainsawExists) {
  console.log('ℹ️  Submodules not initialized. Run "git submodule update --init" first.');
  process.exit(0);
}

try {
  // Update SIGMA rules
  if (sigmaExists) {
    console.log('📦 Updating SIGMA rules from SigmaHQ...');
    execSync('git submodule update --remote src/sigma-master', {
      cwd: projectRoot,
      stdio: 'inherit'
    });
    console.log('✅ SIGMA rules updated\n');
  } else {
    console.log('⚠️  SIGMA submodule not initialized, skipping...\n');
  }

  // Update Chainsaw rules
  if (chainsawExists) {
    console.log('📦 Updating Chainsaw rules...');
    execSync('git submodule update --remote src/chainsaw-rules', {
      cwd: projectRoot,
      stdio: 'inherit'
    });
    console.log('✅ Chainsaw rules updated\n');
  } else {
    console.log('⚠️  Chainsaw submodule not initialized, skipping...\n');
  }

  console.log('🎉 Detection rules sync complete!');
} catch (error) {
  console.error('\n❌ Error syncing detection rules:');
  console.error(error.message);
  process.exit(1);
}
