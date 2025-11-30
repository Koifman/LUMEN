import { useMemo, useState, useCallback, useEffect } from 'react';
import { getAvailablePlatformsWithCounts, SigmaPlatform, PlatformInfo } from '../lib/sigma/utils/autoLoadRules';
import SigmaRuleLoader from './SigmaRuleLoader';
import './SigmaPlatformSelector.css';

interface SigmaPlatformSelectorProps {
  onSelect: (platform: SigmaPlatform, categories: string[]) => void;
  onBack: () => void;
  sigmaEngine?: any;
}

export default function SigmaPlatformSelector({ onSelect, onBack, sigmaEngine }: SigmaPlatformSelectorProps) {
  const [hoveredPlatform, setHoveredPlatform] = useState<string | null>(null);
  const [selectedPlatform, setSelectedPlatform] = useState<SigmaPlatform | null>(null);
  const [showRuleLoader, setShowRuleLoader] = useState(false);
  const [platforms, setPlatforms] = useState<PlatformInfo[]>([]);
  const [availableCategories, setAvailableCategories] = useState<string[]>([]);
  const [selectedCategories, setSelectedCategories] = useState<string[]>([]);

  // Load platforms with dynamic rule counts and categories
  useEffect(() => {
    const loadData = async () => {
      // Load platforms
      const platformsData = await getAvailablePlatformsWithCounts();
      setPlatforms(platformsData);

      // Load categories from manifest
      try {
        const response = await fetch('/sigma-rules/manifest.json');
        if (response.ok) {
          const manifest = await response.json();
          const categories = Object.keys(manifest).sort();
          setAvailableCategories(categories);
        }
      } catch (error) {
        console.warn('Failed to load categories:', error);
      }
    };
    loadData();
  }, []);

  const handlePlatformClick = (platformId: SigmaPlatform) => {
    setSelectedPlatform(platformId);
    // Select all categories by default
    setSelectedCategories(availableCategories);
  };

  const toggleCategory = (cat: string) => {
    setSelectedCategories(prev =>
      prev.includes(cat) ? prev.filter(c => c !== cat) : [...prev, cat]
    );
  };

  const handleLoad = () => {
    if (!selectedPlatform) return;
    onSelect(selectedPlatform, selectedCategories);
  };

  // Handler for when custom rules are loaded
  const handleCustomRulesLoaded = useCallback((_count: number) => {
    setShowRuleLoader(false);
  }, []);

  return (
    <div className="platform-selector">
      <div className="platform-header">
        <button className="back-button" onClick={onBack}>
          ← Back to Analysis Selection
        </button>
        <div className="header-content">
          <div className="logo-container">
            <h1>SIGMA Detection</h1>
            <span className="logo-icon">🛡️</span>
          </div>
          <p className="tagline">Windows Event Log (EVTX) Detection Rules</p>
        </div>
        <button
          onClick={() => setShowRuleLoader(!showRuleLoader)}
          className="load-custom-rules-button"
          style={{
            marginTop: '1rem',
            padding: '0.75rem 1.5rem',
            background: showRuleLoader ? 'var(--accent-orange)' : 'var(--accent-blue)',
            color: 'white',
            border: 'none',
            borderRadius: '6px',
            cursor: 'pointer',
            fontSize: '0.95rem',
            fontWeight: '600',
            transition: 'all 0.2s ease'
          }}
        >
          {showRuleLoader ? '✕ Close Rule Loader' : '📂 Load Custom SIGMA Rules'}
        </button>
      </div>

      {/* Custom Rule Loader */}
      {showRuleLoader && sigmaEngine && (
        <div style={{ marginBottom: '2rem' }}>
          <SigmaRuleLoader
            engine={sigmaEngine}
            onRulesLoaded={handleCustomRulesLoaded}
          />
        </div>
      )}

      <div className="platform-cards">
        {platforms.map((platform) => (
          <div
            key={platform.id}
            className={`platform-card ${platform.id} ${hoveredPlatform === platform.id ? 'hovered' : ''} ${platform.ruleCount === 0 ? 'disabled' : ''}`}
            onClick={() => platform.ruleCount > 0 && handlePlatformClick(platform.id)}
            onMouseEnter={() => setHoveredPlatform(platform.id)}
            onMouseLeave={() => setHoveredPlatform(null)}
          >
            <div className="platform-icon">{platform.icon}</div>
            <div className="platform-content">
              <h3>{platform.name}</h3>
              <p>{platform.description}</p>
              <div className="rule-count">
                <span className="count">{platform.ruleCount.toLocaleString()}</span>
                <span className="label">detection rules</span>
              </div>
            </div>
            <div className="platform-arrow">→</div>
          </div>
        ))}
      </div>

      {selectedPlatform && availableCategories.length > 0 && (
        <div className="platform-filters">
          <div className="filters-header">
            <div>
              <p className="filter-kicker">Rule filters</p>
              <h4>Load only relevant categories</h4>
              <p className="filter-sub">Reducing categories trims load time and noise.</p>
            </div>
            <div className="filter-actions">
              <button onClick={() => setSelectedCategories(availableCategories)}>Select all</button>
              <button onClick={() => setSelectedCategories([])}>Clear</button>
            </div>
          </div>
          <div className="filter-grid">
            {availableCategories.map(cat => (
              <label key={cat} className="filter-chip">
                <input
                  type="checkbox"
                  checked={selectedCategories.includes(cat)}
                  onChange={() => toggleCategory(cat)}
                />
                <span>{cat.replace(/_/g, ' ')}</span>
              </label>
            ))}
          </div>
          <div className="filter-footer">
            <span>{selectedCategories.length} of {availableCategories.length} categories selected</span>
            <button className="load-button" onClick={handleLoad} disabled={selectedCategories.length === 0}>
              Load rules
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
