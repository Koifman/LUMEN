import { useState } from 'react';
import { ParsedData } from '../types';
import SigmaDetections from './SigmaDetections';
import { SigmaEngine } from '../lib/sigma';
import { SigmaRuleMatch } from '../lib/sigma/types';
import './Dashboard.css';

interface DashboardProps {
  data: ParsedData;
  filename: string;
  onBack: () => void;
  sigmaEngine?: SigmaEngine;
  cachedMatches?: Map<string, SigmaRuleMatch[]>;
  onMatchesUpdate?: (matches: Map<string, SigmaRuleMatch[]>) => void;
}

export default function Dashboard({
  data,
  filename,
  onBack,
  sigmaEngine,
  cachedMatches,
  onMatchesUpdate
}: DashboardProps) {
  // Track if analysis is complete - disable back button until done
  const [isAnalysisComplete, setIsAnalysisComplete] = useState(
    cachedMatches ? cachedMatches.size > 0 : false
  );

  // Handle analysis completion
  const handleAnalysisComplete = (matches: Map<string, SigmaRuleMatch[]>) => {
    setIsAnalysisComplete(true);
    if (onMatchesUpdate) {
      onMatchesUpdate(matches);
    }
  };

  return (
    <div className="dashboard">
      <header className="dashboard-header">
        <div>
          <div className="logo-container">
            <h1>LUMEN</h1>
            <span style={{ fontSize: '2rem' }}>🔆</span>
          </div>
          <p className="tagline">Your EVTX companion</p>
          <p className="filename">
            {filename} • {data.entries.length.toLocaleString()} events • Format: {data.format.toUpperCase()}
          </p>
        </div>
        <div className="header-buttons">
          <button
            className={`timeline-button ${!isAnalysisComplete ? 'disabled' : ''}`}
            onClick={isAnalysisComplete ? onBack : undefined}
            disabled={!isAnalysisComplete}
            title={!isAnalysisComplete ? 'Please wait for analysis to complete' : ''}
          >
            {isAnalysisComplete ? '← Back to Selection' : 'Analyzing...'}
          </button>
        </div>
      </header>

      {/* SIGMA Threat Detection Section */}
      {data.format === 'evtx' && (
        <div className="sigma-section">
          <SigmaDetections
            events={data.entries}
            sigmaEngine={sigmaEngine}
            onMatchesUpdate={handleAnalysisComplete}
            cachedMatches={cachedMatches}
            sourceFiles={data.sourceFiles}
          />
        </div>
      )}
    </div>
  );
}
