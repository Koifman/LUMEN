import { useState, useCallback } from 'react';
import { isBinaryEVTX } from '../evtxBinaryParser';
import { parseBinaryEVTXWithWasm } from '../lib/evtxWasmParser';
import { parseLogFile } from '../parser';
import { ParsedData } from '../types';
import { generateSampleData } from '../lib/sampleDataGenerator';
import SampleSelector from './SampleSelector';
import './FileDropZone.css';

interface FileDropZoneProps {
  onFileLoaded: (data: ParsedData, filename: string) => void;
  rulesLoading?: boolean;
  onOpenSessions?: () => void;
}

export default function FileDropZone({ onFileLoaded, rulesLoading, onOpenSessions }: FileDropZoneProps) {
  const [isDragging, setIsDragging] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [processingStatus, setProcessingStatus] = useState('');
  const [eventsProcessed, setEventsProcessed] = useState(0);
  const [totalEvents, setTotalEvents] = useState(0);
  const [chunksProcessed, setChunksProcessed] = useState(0);
  const [totalChunks, setTotalChunks] = useState(0);
  const [showSampleSelector, setShowSampleSelector] = useState(false);
  const [currentFileIndex, setCurrentFileIndex] = useState(0);
  const [totalFiles, setTotalFiles] = useState(0);

  const handleFile = useCallback(
    async (file: File) => {
      setIsProcessing(true);
      setEventsProcessed(0);
      setTotalEvents(0);
      setChunksProcessed(0);
      setTotalChunks(0);
      setProcessingStatus('Checking file format...');

      try {
        // Check file size and enforce 500MB limit
        const fileSizeMB = file.size / 1024 / 1024;
        const MAX_FILE_SIZE_MB = 500;

        if (fileSizeMB > MAX_FILE_SIZE_MB) {
          alert(
            `File too large: ${fileSizeMB.toFixed(1)} MB\n\n` +
            `Maximum file size: ${MAX_FILE_SIZE_MB} MB\n\n` +
            `Please use a smaller log file or filter the events before exporting.`
          );
          setIsProcessing(false);
          return;
        }

        // Check if this is a binary EVTX file
        const isBinary = await isBinaryEVTX(file);

        let xmlContent: string;

        if (isBinary) {
          // For binary EVTX, we can't use chunked reading as the WASM parser needs the complete file
          // Just show a message that we're parsing
          setProcessingStatus(`Parsing binary EVTX file (${fileSizeMB.toFixed(1)} MB)...`);
          xmlContent = await parseBinaryEVTXWithWasm(file, (wasmChunksProcessed, wasmTotalChunks, recordsProcessed) => {
            setChunksProcessed(wasmChunksProcessed);
            setTotalChunks(wasmTotalChunks);
            setProcessingStatus(`Parsed ${recordsProcessed.toLocaleString()} records`);
          });
        } else {
          // Read XML file in chunks to avoid memory issues with large files
          const CHUNK_SIZE = 10 * 1024 * 1024; // 10MB chunks
          const fileChunks = Math.ceil(file.size / CHUNK_SIZE);
          setTotalChunks(fileChunks);

          setProcessingStatus(`Reading file (${fileSizeMB.toFixed(1)} MB)...`);

          xmlContent = await new Promise<string>((resolve, reject) => {
            const chunks: string[] = [];
            let offset = 0;
            let loadedChunks = 0;

            const readNextChunk = () => {
              const blob = file.slice(offset, offset + CHUNK_SIZE);
              const reader = new FileReader();

              reader.onload = (e) => {
                chunks.push(e.target?.result as string);
                offset += CHUNK_SIZE;
                loadedChunks++;

                setChunksProcessed(loadedChunks);
                setProcessingStatus(`Reading file chunks...`);

                if (offset < file.size) {
                  // Read next chunk
                  readNextChunk();
                } else {
                  // All chunks read, combine them
                  resolve(chunks.join(''));
                }
              };

              reader.onerror = () => {
                reject(new Error('Error reading file'));
              };

              reader.readAsText(blob);
            };

            readNextChunk();
          });
        }

        // Parse the XML content with progress tracking
        setProcessingStatus('Parsing events from XML...');
        const parsedData = parseLogFile(xmlContent, (processed, total) => {
          setEventsProcessed(processed);
          setTotalEvents(total);
          setProcessingStatus(`Parsing events: ${processed.toLocaleString()} / ${total.toLocaleString()}`);
        }, file.name);

        // Call parent with parsed data
        setProcessingStatus('Loading analysis selector...');

        // Use setTimeout to yield to browser and update UI before heavy state update
        await new Promise(resolve => setTimeout(resolve, 100));

        onFileLoaded(parsedData, file.name);
        setIsProcessing(false);
      } catch (error) {
        alert(`Error processing file: ${error instanceof Error ? error.message : 'Unknown error'}`);
        setIsProcessing(false);
      }
    },
    [onFileLoaded]
  );

  const handleFiles = useCallback(
    async (files: FileList) => {
      if (files.length === 0) return;

      // If only one file, use the original handler
      if (files.length === 1) {
        handleFile(files[0]);
        return;
      }

      setIsProcessing(true);
      setTotalFiles(files.length);
      setCurrentFileIndex(0);
      setEventsProcessed(0);
      setTotalEvents(0);
      setChunksProcessed(0);
      setTotalChunks(0);

      try {
        const allParsedData: ParsedData[] = [];
        const filenames: string[] = [];

        // Process each file sequentially
        for (let i = 0; i < files.length; i++) {
          const file = files[i];
          setCurrentFileIndex(i + 1);
          setProcessingStatus(`Processing file ${i + 1} of ${files.length}: ${file.name}`);

          // Check file size
          const fileSizeMB = file.size / 1024 / 1024;
          const MAX_FILE_SIZE_MB = 500;

          if (fileSizeMB > MAX_FILE_SIZE_MB) {
            alert(
              `File ${file.name} is too large: ${fileSizeMB.toFixed(1)} MB\n\n` +
              `Maximum file size: ${MAX_FILE_SIZE_MB} MB\n\n` +
              `Skipping this file.`
            );
            continue;
          }

          // Check if binary EVTX
          const isBinary = await isBinaryEVTX(file);
          let xmlContent: string;

          if (isBinary) {
            setProcessingStatus(`[${i + 1}/${files.length}] Parsing binary EVTX: ${file.name}`);
            xmlContent = await parseBinaryEVTXWithWasm(file, (wasmChunksProcessed, wasmTotalChunks, recordsProcessed) => {
              setChunksProcessed(wasmChunksProcessed);
              setTotalChunks(wasmTotalChunks);
              setProcessingStatus(`[${i + 1}/${files.length}] ${file.name}: ${recordsProcessed.toLocaleString()} records`);
            });
          } else {
            // Read XML file
            const CHUNK_SIZE = 10 * 1024 * 1024;
            const fileChunks = Math.ceil(file.size / CHUNK_SIZE);
            setTotalChunks(fileChunks);

            setProcessingStatus(`[${i + 1}/${files.length}] Reading ${file.name}...`);

            xmlContent = await new Promise<string>((resolve, reject) => {
              const chunks: string[] = [];
              let offset = 0;
              let loadedChunks = 0;

              const readNextChunk = () => {
                const blob = file.slice(offset, offset + CHUNK_SIZE);
                const reader = new FileReader();

                reader.onload = (e) => {
                  chunks.push(e.target?.result as string);
                  offset += CHUNK_SIZE;
                  loadedChunks++;
                  setChunksProcessed(loadedChunks);

                  if (offset < file.size) {
                    readNextChunk();
                  } else {
                    resolve(chunks.join(''));
                  }
                };

                reader.onerror = () => reject(new Error(`Error reading ${file.name}`));
                reader.readAsText(blob);
              };

              readNextChunk();
            });
          }

          // Parse XML
          setProcessingStatus(`[${i + 1}/${files.length}] Parsing events from ${file.name}...`);
          const parsedData = parseLogFile(xmlContent, (processed, total) => {
            setEventsProcessed(processed);
            setTotalEvents(total);
            setProcessingStatus(`[${i + 1}/${files.length}] ${file.name}: ${processed.toLocaleString()} / ${total.toLocaleString()} events`);
          }, file.name);

          allParsedData.push(parsedData);
          filenames.push(file.name);

          // Reset progress for next file
          setEventsProcessed(0);
          setTotalEvents(0);
          setChunksProcessed(0);
          setTotalChunks(0);
        }

        // Merge all parsed data
        setProcessingStatus('Merging data from all files...');
        const mergedData: ParsedData = {
          entries: allParsedData.flatMap(data => data.entries),
          format: 'evtx',
          totalLines: allParsedData.reduce((sum, data) => sum + data.totalLines, 0),
          parsedLines: allParsedData.reduce((sum, data) => sum + data.parsedLines, 0),
          sourceFiles: filenames,
        };

        // Load analysis selector
        setProcessingStatus('Loading analysis selector...');
        await new Promise(resolve => setTimeout(resolve, 100));

        onFileLoaded(mergedData, filenames.join(', '));
        setIsProcessing(false);
        setCurrentFileIndex(0);
        setTotalFiles(0);
      } catch (error) {
        alert(`Error processing files: ${error instanceof Error ? error.message : 'Unknown error'}`);
        setIsProcessing(false);
        setCurrentFileIndex(0);
        setTotalFiles(0);
      }
    },
    [onFileLoaded, handleFile]
  );

  const handleSampleSelect = useCallback(
    async (url: string, filename: string) => {
      setShowSampleSelector(false);
      setIsProcessing(true);
      setEventsProcessed(0);
      setTotalEvents(0);
      setChunksProcessed(0);
      setTotalChunks(0);
      setProcessingStatus('Fetching sample file...');

      try {
        // Fetch the sample EVTX file
        const response = await fetch(url);
        if (!response.ok) {
          throw new Error(`Failed to fetch sample: ${response.statusText}`);
        }

        // Get as blob and convert to File
        const blob = await response.blob();
        const file = new File([blob], filename, { type: 'application/octet-stream' });

        // Process the file
        setProcessingStatus('Parsing sample EVTX file...');
        const xmlContent = await parseBinaryEVTXWithWasm(file, (wasmChunksProcessed, wasmTotalChunks, recordsProcessed) => {
          setChunksProcessed(wasmChunksProcessed);
          setTotalChunks(wasmTotalChunks);
          setProcessingStatus(`Parsed ${recordsProcessed.toLocaleString()} records`);
        });

        // Parse the XML content with progress tracking
        setProcessingStatus('Parsing events from XML...');
        const parsedData = parseLogFile(xmlContent, (processed, total) => {
          setEventsProcessed(processed);
          setTotalEvents(total);
          setProcessingStatus(`Parsing events: ${processed.toLocaleString()} / ${total.toLocaleString()}`);
        });

        setProcessingStatus('Loading analysis selector...');
        await new Promise(resolve => setTimeout(resolve, 100));

        onFileLoaded(parsedData, filename);
        setIsProcessing(false);
      } catch (error) {
        alert(`Error loading sample: ${error instanceof Error ? error.message : 'Unknown error'}`);
        setIsProcessing(false);
      }
    },
    [onFileLoaded]
  );

  const handleDrop = useCallback(
    (e: React.DragEvent<HTMLDivElement>) => {
      e.preventDefault();
      setIsDragging(false);

      const files = e.dataTransfer.files;
      if (files.length > 0) {
        handleFiles(files);
      }
    },
    [handleFiles]
  );

  const handleDragOver = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
  }, []);

  const handleFileInput = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const files = e.target.files;
      if (files && files.length > 0) {
        handleFiles(files);
      }
    },
    [handleFiles]
  );

  const handleSampleData = useCallback(() => {
    const sampleData = generateSampleData();
    onFileLoaded(sampleData, 'sample_data.evtx');
  }, [onFileLoaded]);

  return (
    <div className={`drop-zone ${rulesLoading ? 'disabled' : ''}`}>
      <div
        className={`drop-zone-content ${isDragging ? 'dragging' : ''}`}
        onDrop={rulesLoading ? undefined : handleDrop}
        onDragOver={rulesLoading ? undefined : handleDragOver}
        onDragLeave={rulesLoading ? undefined : handleDragLeave}
      >
        <div className="icon">📁</div>
        {rulesLoading ? (
          <>
            <h2>Loading SIGMA Rules...</h2>
            <p>Please wait while security detection rules are being loaded</p>
            <div className="processing">Loading rules from /src/rules...</div>
          </>
        ) : (
          <>
            <h2>Drop your EVTX/XML file(s) here</h2>
            <p>Windows Event Log files (.evtx) - binary or XML export</p>
            <p className="info-note">💡 You can select multiple files at once</p>
            <p className="info-note">💡 File size limit: 500MB per file</p>
        <p className="privacy-note">🔒 100% client-side processing - your data never leaves your computer (except when using AI analysis)</p>

            <label className="file-input-label">
              <input
                type="file"
                accept=".evtx,.xml"
                onChange={handleFileInput}
                style={{ display: 'none' }}
                disabled={rulesLoading || isProcessing}
                multiple
              />
              <span className="button">Or click to browse</span>
            </label>

            <div className="secondary-buttons">
              <button
                className="sample-data-button"
                onClick={handleSampleData}
                disabled={rulesLoading || isProcessing}
              >
                Quick demo
              </button>
              <button
                className="sample-data-button attack-samples"
                onClick={() => setShowSampleSelector(true)}
                disabled={rulesLoading || isProcessing}
              >
                Load attack samples
              </button>
              {onOpenSessions && (
                <button
                  className="sessions-button"
                  onClick={onOpenSessions}
                  disabled={rulesLoading || isProcessing}
                >
                  💾 Load saved session
                </button>
              )}
            </div>

            {isProcessing && (
              <div className="processing-container">
                <div className="processing-status">{processingStatus}</div>
                {totalFiles > 1 && (
                  <div className="file-progress">
                    File {currentFileIndex} of {totalFiles}
                  </div>
                )}
                {totalChunks > 0 && (
                  <div className="chunk-progress">
                    {chunksProcessed} / {totalChunks} chunks
                  </div>
                )}
                {totalEvents > 0 && (
                  <div className="processing-events">
                    {eventsProcessed.toLocaleString()} / {totalEvents.toLocaleString()} events
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </div>

      {showSampleSelector && (
        <SampleSelector
          onSelectSample={handleSampleSelect}
          onClose={() => setShowSampleSelector(false)}
        />
      )}
    </div>
  );
}
