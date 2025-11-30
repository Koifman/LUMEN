import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { copyFileSync, mkdirSync, readdirSync, statSync } from 'fs'
import { join } from 'path'

// Plugin to copy samples folder to dist during build
function copySamplesPlugin() {
  return {
    name: 'copy-samples',
    closeBundle() {
      const shouldExclude = (entry: string) => {
        // Exclude hidden files, git files, and common unwanted files
        return entry.startsWith('.') ||
               entry === '.git' ||
               entry === '.gitignore' ||
               entry === '.DS_Store' ||
               entry === 'Thumbs.db' ||
               entry === 'desktop.ini';
      };

      const shouldIncludeFile = (filename: string) => {
        // Only include EVTX files (case-insensitive)
        return filename.toLowerCase().endsWith('.evtx');
      };

      const copyRecursive = (src: string, dest: string) => {
        try {
          mkdirSync(dest, { recursive: true });
          const entries = readdirSync(src);
          for (const entry of entries) {
            // Skip excluded files/folders
            if (shouldExclude(entry)) {
              continue;
            }

            const srcPath = join(src, entry);
            const destPath = join(dest, entry);
            if (statSync(srcPath).isDirectory()) {
              copyRecursive(srcPath, destPath);
            } else {
              // Only copy EVTX files
              if (shouldIncludeFile(entry)) {
                copyFileSync(srcPath, destPath);
                console.log(`Copied: ${srcPath} -> ${destPath}`);
              }
            }
          }
        } catch (error) {
          console.warn(`Failed to copy samples: ${error}`);
        }
      };
      copyRecursive('samples', 'dist/samples');
    }
  }
}

export default defineConfig({
  plugins: [react(), copySamplesPlugin()],

  // Enable WASM support
  assetsInclude: ['**/*.wasm'],

  optimizeDeps: {
    exclude: ['evtx_wasm.js']
  },

  // Build configuration
  build: {
    rollupOptions: {
      output: {
        // Code splitting - separate chunks for LLM providers and heavy UI libraries
        // Only load when user actually uses that feature
        manualChunks: {
          'vendor-llm-openai': ['openai', 'jspdf'],
          'vendor-llm-anthropic': ['@anthropic-ai/sdk'],
          'vendor-llm-google': ['@google/genai'],
          'vendor-ui': ['react', 'react-dom'],
          'vendor-charts': ['recharts'],
          'vendor-markdown': ['react-markdown'],
        }
      }
    }
  },

  server: {
    fs: {
      // Allow serving files from samples and public
      allow: ['..']
    }
  }
})
