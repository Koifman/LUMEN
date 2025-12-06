# LUMEN — Client‑Side EVTX Companion

![](https://miro.medium.com/v2/resize:fit:4800/format:webp/1*baIkQcUohn7SJl9ULbBUcw.png)

LUMEN is a browser-based Windows Event Log analyzer that stays entirely on your machine. Load EVTX files, run curated SIGMA detections, correlate activity into storylines, extract IOCs, and export findings—without sending logs anywhere. If you are interested in contributing, feel free to check out the [guidelines](https://github.com/Koifman/LUMEN/blob/main/CONTRIBUTING.md).

## What it does
- **Multi-file upload**: Upload multiple EVTX files simultaneously with merged analysis and file-based filtering for comprehensive investigations across entire log folders.
- **Guided investigations**: A collapsible side-rail keeps you on track from ingest → detections → correlation → export.
- **Curated SIGMA loads**: Pick platform (Windows/Linux/macOS/Cloud/Network) and filter rule categories before loading to reduce noise and speed up matching.
- **Custom SIGMA rules**: Upload and manage your own SIGMA rules for organization-specific detections alongside curated rules.
- **Detection & triage**: Severity-tagged matches with cached results across views; supports large-but-reasonable files with warnings above 25k events.
- **Correlation & story view**: Chains related events, with a narrative "Storyline" tab for fast triage and a detailed chain view with process context.
- **IOC extraction + VT integration**: Pull IPs/domains/hashes/paths/URLs/registry keys; optional VirusTotal lookups with API key input.
- **Dashboards & timeline**: High-level dashboards, process analysis, and a SIGMA-aware timeline for sequence analysis.
- **Process masquerading detection**: Levenshtein distance-based detection of process names similar to legitimate Windows processes with customizable threshold and exclusion lists.
- **Suspicious location analysis**: Automatic flagging of processes executed from temporary, download, or public folders with grouping by process name and parent.
- **Sessions & exports**: Save/restore sessions locally (no server), export reports, and use built-in sample data for demos.
- **Privacy by design**: 100% client-side (WASM + JS); no telemetry, no uploads.

## Quickstart
```bash
git clone --recurse-submodules https://github.com/Koifman/LUMEN.git
cd LUMEN
npm install
npm run build # You have to do this since we get the rule numbers/categories from a manifest file generated at build
npm run dev  # app at http://localhost:5173
```

If you already cloned without submodules:
```bash
git submodule update --init --recursive
```

## Workflow
1) **Upload logs**: Drag/drop single or multiple EVTX files, or load samples. File size limit: 1GB per file. Supports both binary EVTX and XML exports. Multi-file uploads are automatically merged for cross-file analysis with color-coded visualization and file filtering.
2) **Select analysis**: SIGMA Detection, Event Correlation, Dashboards, Timeline, IOC Extraction, Raw Logs, AI Analysis.
3) **Load SIGMA**: Choose platform and (optionally) categories; rules load dynamically and cache for the session. Upload custom SIGMA rules for organization-specific detections.
4) **Investigate**:
   - Detections: severity-filtered results with rule details; filter by source file when analyzing multiple files.
   - Correlation: Analyzes events with SIGMA matches (+ context events); chain list + Storyline summary for fast triage.
   - IOC Extraction: categorized indicators, VT lookup buttons, export IOCs.
   - Dashboards/Timeline/Process views: aggregated and time-sequenced perspectives with file breakdown statistics.
   - Process Execution Analysis: Detects masquerading attempts using Levenshtein distance matching (customizable threshold 1-5) against 166+ legitimate Windows processes; flags processes from suspicious locations (temp folders, downloads, etc.); supports path/process exclusions with editable legitimate process list.
   - AI Analysis: Optional AI-powered analysis using Anthropic Claude, OpenAI, Google Gemini, or Ollama.
5) **Export or save**: Generate reports or save a session locally to resume later.

## Architecture (high level)
- **React + Vite** frontend; heavy views lazy-loaded to trim initial bundle.
- **SIGMA engine** (`src/lib/sigma/`): parser, compiler, matcher with platform/category-scoped loading from `src/sigma-master`; supports custom rule uploads.
- **Correlation engine** (`src/lib/correlationEngine.ts`): links SIGMA-matched events into chains using process/temporal relationships.
- **EVTX parsing**: WASM-backed parsing (using evtx Rust library) with chunked processing for large files; supports both binary EVTX and XML exports; multi-file upload with merged analysis.
- **Multi-file support**: File source tracking, color-coded visualization, file filtering, and breakdown statistics for analyzing multiple log files simultaneously.
- **Persistence**: `localStorage`-based session save/restore (metadata index + compressed payload); supports multi-file sessions.

## Testing & samples
- Built-in sample loader plus `samples/EVTX-ATTACK-SAMPLES` for quick demos.


## License
MIT — see [LICENSE](LICENSE).
