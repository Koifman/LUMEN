import { useState, useMemo, lazy, Suspense } from 'react';
import FileDropZone from './components/FileDropZone';
import AnalysisSelector, { AnalysisMode } from './components/AnalysisSelector';
import Dashboard from './components/Dashboard';
const LazySigmaPlatformSelector = lazy(() => import('./components/SigmaPlatformSelector'));
const LazyDashboards = lazy(() => import('./components/Dashboards'));
const LazyProcessExecutionDashboard = lazy(() => import('./components/ProcessExecutionDashboard'));
const LazyTimeline = lazy(() => import('./components/Timeline'));
const LazyRawLogsView = lazy(() => import('./components/RawLogsView'));
const LazyLLMAnalysis = lazy(() => import('./components/LLMAnalysis'));
import SessionManager from './components/SessionManager';
import { ParsedData } from './types';
import { createSigmaEngine, SigmaEngine } from './lib/sigma';
import { SigmaRuleMatch } from './lib/sigma/types';
import type { SigmaPlatform } from './lib/sigma/utils/autoLoadRules';
import SigmaDetections from './components/SigmaDetections';
import { ErrorBoundary, FileOperationErrorBoundary, AnalysisErrorBoundary } from './components/ErrorBoundary';
import LoadingState from './components/LoadingState';
import './components/Dashboard.css';

const LazyIOCExtractor = lazy(() => import('./components/IOCExtractor'));
const LazyEventCorrelation = lazy(() => import('./components/EventCorrelation'));

type AppView = 'upload' | 'select' | 'sigma-platform' | 'analysis';

function App() {
  const [parsedData, setParsedData] = useState<ParsedData | null>(null);
  const [filename, setFilename] = useState<string>('');
  const [rulesLoading, setRulesLoading] = useState(false);
  const [ruleLoadProgress, setRuleLoadProgress] = useState<{ loaded: number; total: number } | null>(null);
  const [currentView, setCurrentView] = useState<AppView>('upload');
  const [analysisMode, setAnalysisMode] = useState<AnalysisMode | null>(null);
  const [sigmaMatches, setSigmaMatches] = useState<Map<string, SigmaRuleMatch[]>>(new Map());
  const [selectedPlatform, setSelectedPlatform] = useState<SigmaPlatform | null>(null);
  const [showSessionManager, setShowSessionManager] = useState(false);
  const [showOpenSourceAnnouncement, setShowOpenSourceAnnouncement] = useState(() => {
    // Show popup only once
    const hasSeenAnnouncement = localStorage.getItem('hasSeenOpenSourceAnnouncement');
    return !hasSeenAnnouncement;
  });

  // Create SIGMA engine instance (persists across renders)
  const sigmaEngine = useMemo(() => {
    return createSigmaEngine({
      autoCompile: true,
      enableRegex: true,
      strictValidation: false
    });
  }, []);

  const handleFileLoaded = (data: ParsedData, name: string) => {
    setParsedData(data);
    setFilename(name);
    setCurrentView('select');
  };

  const handleReset = () => {
    setParsedData(null);
    setFilename('');
    setAnalysisMode(null);
    setSigmaMatches(new Map());
    setSelectedPlatform(null);
    // Clear loaded rules from engine
    sigmaEngine.clearRules();
    setCurrentView('upload');
  };

  const handleAnalysisSelect = (mode: AnalysisMode) => {
    if (mode === 'sigma') {
      // If we already have cached matches, go directly to analysis
      // Otherwise show platform selector
      if (sigmaMatches.size > 0 && selectedPlatform) {
        setAnalysisMode('sigma');
        setCurrentView('analysis');
      } else {
        setCurrentView('sigma-platform');
      }
    } else {
      setAnalysisMode(mode);
      setCurrentView('analysis');
    }
  };

  const handlePlatformSelect = async (platform: SigmaPlatform, categories: string[]) => {
    setSelectedPlatform(platform);
    setRulesLoading(true);

    // Clear any previously loaded rules
    sigmaEngine.clearRules();
    setSigmaMatches(new Map());
    setRuleLoadProgress(null);

    // Load rules for selected platform with progress tracking
    const { autoLoadRules } = await import('./lib/sigma/utils/autoLoadRules');
    await autoLoadRules(
      sigmaEngine,
      platform,
      (loaded, total) => setRuleLoadProgress({ loaded, total }),
      categories
    );

    setRulesLoading(false);
    setRuleLoadProgress(null);

    // Switch to analysis view only after rules are loaded
    setAnalysisMode('sigma');
    setCurrentView('analysis');
  };

  const handleBackToSelector = () => {
    setCurrentView('select');
    setAnalysisMode(null);
  };

  const handleBackFromPlatformSelector = () => {
    setCurrentView('select');
  };

  const handleLoadSession = (
    data: ParsedData,
    name: string,
    platform: string | null,
    matches: Map<string, SigmaRuleMatch[]>,
    _conversation?: { provider: string; model: string; messages: any[] }
  ) => {
    setParsedData(data);
    setFilename(name);
    setSelectedPlatform(platform as SigmaPlatform | null);
    setSigmaMatches(matches);
    setCurrentView('select');
    // Note: conversation history will be handled by LLMAnalysis when it mounts
    // For now, we don't persist it in App state
  };

  // Render based on current view
  let content: JSX.Element;

  if (currentView === 'upload' || !parsedData) {
    content = (
      <FileOperationErrorBoundary>
        <FileDropZone
          onFileLoaded={handleFileLoaded}
          rulesLoading={rulesLoading}
          onOpenSessions={() => setShowSessionManager(true)}
        />
      </FileOperationErrorBoundary>
    );
  } else if (currentView === 'select') {
    content = (
      <ErrorBoundary>
        <AnalysisSelector
          data={parsedData}
          filename={filename}
          onSelect={handleAnalysisSelect}
          onReset={handleReset}
          onOpenSessions={() => setShowSessionManager(true)}
          sigmaMatches={sigmaMatches}
          platform={selectedPlatform}
        />
      </ErrorBoundary>
    );
  } else if (currentView === 'sigma-platform') {
    content = (
      <ErrorBoundary>
        <Suspense fallback={<LoadingState message="Loading platform selector..." />}>
          <LazySigmaPlatformSelector
            onSelect={handlePlatformSelect}
            onBack={handleBackFromPlatformSelector}
            sigmaEngine={sigmaEngine}
          />
        </Suspense>
      </ErrorBoundary>
    );
  } else if (analysisMode === 'sigma') {
    content = (
      <AnalysisErrorBoundary>
        <SigmaAnalysisView
          data={parsedData}
          filename={filename}
          sigmaEngine={sigmaEngine}
          platform={selectedPlatform}
          rulesLoading={rulesLoading}
          ruleLoadProgress={ruleLoadProgress}
          onBack={handleBackToSelector}
          cachedMatches={sigmaMatches}
          onMatchesUpdate={setSigmaMatches}
        />
      </AnalysisErrorBoundary>
    );
  } else if (analysisMode === 'dashboards') {
    content = (
      <AnalysisErrorBoundary>
        <Suspense fallback={<LoadingState message="Loading dashboards..." fullPage />}>
          <LazyDashboards
            data={parsedData}
            onBack={handleBackToSelector}
          />
        </Suspense>
      </AnalysisErrorBoundary>
    );
  } else if (analysisMode === 'process-analysis') {
    content = (
      <AnalysisErrorBoundary>
        <Suspense fallback={<LoadingState message="Loading process analysis..." fullPage />}>
          <LazyProcessExecutionDashboard
            entries={parsedData.entries}
            onBack={handleBackToSelector}
          />
        </Suspense>
      </AnalysisErrorBoundary>
    );
  } else if (analysisMode === 'timeline') {
    content = (
      <AnalysisErrorBoundary>
        <Suspense fallback={<LoadingState message="Loading timeline..." fullPage />}>
          <TimelineAnalysisView
            data={parsedData}
            filename={filename}
            sigmaEngine={sigmaEngine}
            sigmaMatches={sigmaMatches}
            setSigmaMatches={setSigmaMatches}
            onBack={handleBackToSelector}
          />
        </Suspense>
      </AnalysisErrorBoundary>
    );
  } else if (analysisMode === 'raw-logs') {
    content = (
      <ErrorBoundary>
        <Suspense fallback={<LoadingState message="Loading raw logs..." fullPage />}>
          <LazyRawLogsView
            data={parsedData}
            filename={filename}
            onBack={handleBackToSelector}
          />
        </Suspense>
      </ErrorBoundary>
    );
  } else if (analysisMode === 'ai-analysis') {
    content = (
      <AnalysisErrorBoundary>
        <Suspense fallback={<LoadingState message="Loading AI analysis..." fullPage />}>
          <LazyLLMAnalysis
            data={parsedData}
            sigmaMatches={sigmaMatches}
            onBack={handleBackToSelector}
          />
        </Suspense>
      </AnalysisErrorBoundary>
    );
  } else if (analysisMode === 'ioc-extraction') {
    content = (
      <AnalysisErrorBoundary>
        <Suspense fallback={<LoadingState message="Loading IOC extractor..." fullPage />}>
          <LazyIOCExtractor
            entries={parsedData.entries}
            onBack={handleBackToSelector}
          />
        </Suspense>
      </AnalysisErrorBoundary>
    );
  } else if (analysisMode === 'event-correlation') {
    content = (
      <AnalysisErrorBoundary>
        <Suspense fallback={<LoadingState message="Loading correlation view..." fullPage />}>
          <LazyEventCorrelation
            entries={parsedData.entries}
            sigmaMatches={sigmaMatches}
            onBack={handleBackToSelector}
            data={parsedData}
            filename={filename}
            platform={selectedPlatform}
          />
        </Suspense>
      </AnalysisErrorBoundary>
    );
  } else {
    content = (
      <ErrorBoundary>
        <AnalysisSelector
          data={parsedData}
          filename={filename}
          onSelect={handleAnalysisSelect}
          onReset={handleReset}
        />
      </ErrorBoundary>
    );
  }

  const sessionContext = parsedData ? {
    currentData: parsedData,
    currentFilename: filename,
    currentPlatform: selectedPlatform,
    currentMatches: sigmaMatches,
    currentConversation: undefined // Conversation managed by LLMAnalysis
  } : {
    currentData: null,
    currentFilename: '',
    currentPlatform: null as SigmaPlatform | null,
    currentMatches: new Map<string, SigmaRuleMatch[]>(),
    currentConversation: undefined
  };

  return (
    <div className="app">
      <div className="app-main">
        {content}
      </div>

      {showSessionManager && (
        <SessionManager
          {...sessionContext}
          onLoadSession={handleLoadSession}
          onClose={() => setShowSessionManager(false)}
        />
      )}

      {showOpenSourceAnnouncement && (
        <div className="feedback-modal-backdrop" onClick={() => {
          setShowOpenSourceAnnouncement(false);
          localStorage.setItem('hasSeenOpenSourceAnnouncement', 'true');
        }}>
          <div className="feedback-modal opensource-announcement" onClick={e => e.stopPropagation()}>
            <h3>🎉 LUMEN is Now Open Source!</h3>
            <p>
              LUMEN is now available as an open-source project on GitHub.
              We welcome contributions, bug reports, and feature requests from the community!
            </p>
            <div className="opensource-features">
              <div>✨ Free forever</div>
              <div>🔧 Community-driven</div>
              <div>🚀 Actively maintained</div>
            </div>
            <a
              href="https://github.com/Koifman/LUMEN"
              target="_blank"
              rel="noopener noreferrer"
              className="opensource-link"
            >
              View on GitHub →
            </a>
            <button className="feedback-close" onClick={() => {
              setShowOpenSourceAnnouncement(false);
              localStorage.setItem('hasSeenOpenSourceAnnouncement', 'true');
            }}>Got it!</button>
          </div>
        </div>
      )}
    </div>
  );
}

// SIGMA Analysis View Component
interface SigmaAnalysisViewProps {
  data: ParsedData;
  filename: string;
  sigmaEngine: SigmaEngine;
  platform: SigmaPlatform | null;
  rulesLoading: boolean;
  ruleLoadProgress: { loaded: number; total: number } | null;
  onBack: () => void;
  onMatchesUpdate: (matches: Map<string, SigmaRuleMatch[]>) => void;
  cachedMatches: Map<string, SigmaRuleMatch[]>;
}

function SigmaAnalysisView({
  data,
  filename,
  sigmaEngine,
  platform: _platform,
  rulesLoading: _rulesLoading,
  ruleLoadProgress: _ruleLoadProgress,
  onBack,
  onMatchesUpdate,
  cachedMatches
}: SigmaAnalysisViewProps) {
  // Skip loading screen - rules load in background
  return (
    <Dashboard
      data={data}
      filename={filename}
      onBack={onBack}
      sigmaEngine={sigmaEngine}
      onMatchesUpdate={onMatchesUpdate}
      cachedMatches={cachedMatches}
    />
  );
}

// Timeline Analysis View Component
interface TimelineAnalysisViewProps {
  data: ParsedData;
  filename: string;
  sigmaEngine: SigmaEngine;
  sigmaMatches: Map<string, SigmaRuleMatch[]>;
  setSigmaMatches: (matches: Map<string, SigmaRuleMatch[]>) => void;
  onBack: () => void;
}

function TimelineAnalysisView({
  data,
  sigmaEngine,
  sigmaMatches,
  setSigmaMatches,
  onBack
}: TimelineAnalysisViewProps) {
  const [hasProcessed, setHasProcessed] = useState(sigmaMatches.size > 0);

  // If no SIGMA matches yet, show a processing state or run detection
  if (sigmaMatches.size === 0 && !hasProcessed) {
    return (
      <div className="dashboard">
        <div className="dashboard-header">
          <div>
            <h1>Threat Timeline</h1>
            <p className="tagline">Processing SIGMA detections...</p>
          </div>
          <button className="timeline-button" onClick={onBack}>
            ← Back to Selection
          </button>
        </div>
        <section className="sigma-section">
          <SigmaDetections
            events={data.entries}
            sigmaEngine={sigmaEngine}
            onMatchesUpdate={(matches) => {
              setSigmaMatches(matches);
              setHasProcessed(true);
            }}
            cachedMatches={sigmaMatches}
          />
        </section>
      </div>
    );
  }

  return (
    <LazyTimeline
      matches={sigmaMatches}
      onBack={onBack}
    />
  );
}

export default App;
