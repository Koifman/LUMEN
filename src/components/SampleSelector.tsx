import { useState, useEffect } from 'react';
import './SampleSelector.css';

interface Sample {
  name: string;
  file: string;
  category: string;
}

interface Category {
  name: string;
  description: string;
  sampleCount: number;
  samples: Sample[];
}

interface SamplesManifest {
  categories: Category[];
  generatedAt: string;
  totalSamples: number;
}

interface SampleSelectorProps {
  onSelectSample: (url: string, filename: string) => void;
  onSelectMultipleSamples?: (samples: Array<{ url: string; filename: string }>) => void;
  onClose: () => void;
}

export default function SampleSelector({ onSelectSample, onSelectMultipleSamples, onClose }: SampleSelectorProps) {
  const [manifest, setManifest] = useState<SamplesManifest | null>(null);
  const [selectedCategory, setSelectedCategory] = useState<string>('');
  const [loading, setLoading] = useState<string | null>(null);
  const [loadingAll, setLoadingAll] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Load manifest on mount
  useEffect(() => {
    fetch('/samples-manifest.json')
      .then(res => res.json())
      .then((data: SamplesManifest) => {
        setManifest(data);
        // Set first category as default
        if (data.categories.length > 0) {
          setSelectedCategory(data.categories[0].name);
        }
      })
      .catch(err => {
        console.error('Failed to load samples manifest:', err);
        setError('Failed to load samples list. Please ensure the project was built correctly.');
      });
  }, []);

  const currentCategory = manifest?.categories.find(c => c.name === selectedCategory);

  const handleSelectSample = async (sample: Sample) => {
    setLoading(sample.file);
    // Build the URL to the sample file using the sample's category
    const url = `/samples/EVTX-ATTACK-SAMPLES/${sample.category}/${sample.file}`;
    onSelectSample(url, sample.file);
  };

  const handleLoadAllInCategory = () => {
    if (!currentCategory || !onSelectMultipleSamples) return;

    setLoadingAll(true);
    // Build URLs for all samples in the current category
    const samples = currentCategory.samples.map(sample => ({
      url: `/samples/EVTX-ATTACK-SAMPLES/${sample.category}/${sample.file}`,
      filename: sample.file
    }));

    onSelectMultipleSamples(samples);
  };

  return (
    <div className="sample-selector-overlay" onClick={onClose}>
      <div className="sample-selector-modal" onClick={e => e.stopPropagation()}>
        <div className="sample-selector-header">
          <h2>Load Sample EVTX File</h2>
          <button className="close-btn" onClick={onClose}>×</button>
        </div>

        <div className="sample-selector-content">
          {error && (
            <div className="error-message">
              {error}
            </div>
          )}

          {!manifest && !error && (
            <div className="loading-message">
              Loading samples...
            </div>
          )}

          {manifest && (
            <>
              <div className="category-tabs">
                {manifest.categories.map(cat => (
                  <button
                    key={cat.name}
                    className={`category-tab ${selectedCategory === cat.name ? 'active' : ''}`}
                    onClick={() => setSelectedCategory(cat.name)}
                  >
                    {cat.name}
                    <span className="category-count">({cat.sampleCount})</span>
                  </button>
                ))}
              </div>

              {currentCategory && (
                <div className="sample-list">
                  <div className="category-header">
                    <p className="category-description">{currentCategory.description}</p>
                    {onSelectMultipleSamples && currentCategory.sampleCount > 1 && (
                      <button
                        className={`load-all-button ${loadingAll ? 'loading' : ''}`}
                        onClick={handleLoadAllInCategory}
                        disabled={loading !== null || loadingAll}
                      >
                        {loadingAll ? 'Loading...' : `Load All ${currentCategory.sampleCount} Samples`}
                      </button>
                    )}
                  </div>
                  {currentCategory.samples.map(sample => (
                    <button
                      key={sample.file}
                      className={`sample-item ${loading === sample.file ? 'loading' : ''}`}
                      onClick={() => handleSelectSample(sample)}
                      disabled={loading !== null || loadingAll}
                    >
                      <span className="sample-name">{sample.name}</span>
                      <span className="sample-file">{sample.file}</span>
                      {loading === sample.file && <span className="loading-spinner" />}
                    </button>
                  ))}
                </div>
              )}
            </>
          )}
        </div>

        <div className="sample-selector-footer">
          <p className="credit">
            Samples from <a href="https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES" target="_blank" rel="noopener noreferrer">EVTX-ATTACK-SAMPLES</a> by @sbousseaden
            {manifest && <span className="total-samples"> • {manifest.totalSamples} total samples</span>}
          </p>
        </div>
      </div>
    </div>
  );
}
