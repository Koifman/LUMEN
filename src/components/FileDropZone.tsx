import { useState, useCallback } from 'react';
import { isBinaryEVTX } from '../evtxBinaryParser';
import { parseBinaryEVTXToEntries } from '../lib/evtxWasmParser';
import { parseLogFile } from '../parser';
import { ParsedData } from '../types';
import { generateSampleData } from '../lib/sampleDataGenerator';
import SampleSelector from './SampleSelector';
import { FileProcessingResultsModal } from './FileProcessingResultsModal';
import {
  FileProcessingResult,
  FileProcessingError,
  ErrorType,
  MultiFileProcessingResults,
} from '../types/fileProcessing';
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
  const [chunksProcessed, setChunksProcessed] = useState(0);
  const [totalChunks, setTotalChunks] = useState(0);
  const [showSampleSelector, setShowSampleSelector] = useState(false);
  const [currentFileIndex, setCurrentFileIndex] = useState(0);
  const [totalFiles, setTotalFiles] = useState(0);
  const [showProcessingResults, setShowProcessingResults] = useState(false);
  const [processingResults, setProcessingResults] = useState<MultiFileProcessingResults | null>(null);

  const handleFile = useCallback(
    async (file: File) => {
      setIsProcessing(true);
      setChunksProcessed(0);
      setTotalChunks(0);
      setProcessingStatus('Checking file format...');

      try {
        // Check file size and enforce limit
        // Increased from 500MB to 1000MB (1GB) due to memory optimization (direct WASM→LogEntry conversion)
        const fileSizeMB = file.size / 1024 / 1024;
        const MAX_FILE_SIZE_MB = 1000;

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

        if (isBinary) {
          // Memory-optimized path: Direct WASM → LogEntry conversion (no intermediate XML)
          setProcessingStatus(`Parsing binary EVTX file (${fileSizeMB.toFixed(1)} MB)...`);

          const entries = await parseBinaryEVTXToEntries(
            file,
            (processed, total) => {
              const totalDisplay = total ? total.toLocaleString() : 'unknown';
              const percentage = total > 0 ? ` (${Math.round((processed / total) * 100)}%)` : '';
              setProcessingStatus(`${processed.toLocaleString()} / ${totalDisplay} records${percentage}`);
            },
            file.name
          );

          // Create ParsedData directly from entries
          const parsedData: ParsedData = {
            entries,
            format: 'evtx',
            totalLines: entries.length,
            parsedLines: entries.length,
            sourceFiles: [file.name],
          };

          setProcessingStatus('Loading analysis selector...');
          await new Promise(resolve => setTimeout(resolve, 100));

          onFileLoaded(parsedData, file.name);
          setIsProcessing(false);
        } else {
          // XML path: Read file in chunks and parse with DOMParser
          const CHUNK_SIZE = 10 * 1024 * 1024; // 10MB chunks
          const fileChunks = Math.ceil(file.size / CHUNK_SIZE);
          setTotalChunks(fileChunks);

          setProcessingStatus(`Reading file (${fileSizeMB.toFixed(1)} MB)...`);

          const xmlContent = await new Promise<string>((resolve, reject) => {
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

          // Parse the XML content with progress tracking
          setProcessingStatus('Parsing events from XML...');
          const parsedData = parseLogFile(xmlContent, (processed, total) => {
            setProcessingStatus(`Parsing events: ${processed.toLocaleString()} / ${total.toLocaleString()}`);
          }, file.name);

          // Call parent with parsed data
          setProcessingStatus('Loading analysis selector...');

          // Use setTimeout to yield to browser and update UI before heavy state update
          await new Promise(resolve => setTimeout(resolve, 100));

          onFileLoaded(parsedData, file.name);
          setIsProcessing(false);
        }
      } catch (error) {
        alert(`Error processing file: ${error instanceof Error ? error.message : 'Unknown error'}`);
        setIsProcessing(false);
      }
    },
    [onFileLoaded]
  );

  // Helper function to categorize WASM parser errors
  const categorizeWasmError = (error: unknown, filename: string): FileProcessingError => {
    const errorMsg = error instanceof Error ? error.message : String(error);

    // No records parsed
    if (errorMsg.includes('No records were successfully parsed')) {
      return {
        type: ErrorType.NO_RECORDS_FOUND,
        message: 'No valid event records could be extracted from this file',
        technicalDetails: errorMsg,
        failurePoint: 'parsing',
      };
    }

    // WASM initialization error
    if (errorMsg.includes('WASM') || errorMsg.includes('WebAssembly')) {
      return {
        type: ErrorType.WASM_INITIALIZATION_ERROR,
        message: 'Failed to initialize the binary parser',
        technicalDetails: errorMsg,
        failurePoint: 'parsing',
      };
    }

    // Invalid format
    if (errorMsg.includes('Invalid EVTX') || errorMsg.includes('ElfFile')) {
      return {
        type: ErrorType.INVALID_FORMAT,
        message: 'File does not appear to be a valid EVTX file',
        technicalDetails: errorMsg,
        failurePoint: 'validation',
      };
    }

    // BigInt errors (indicate corrupted timestamps)
    if (errorMsg.includes("can't be represented as a JavaScript number")) {
      return {
        type: ErrorType.CORRUPTED_FILE,
        message: 'File contains corrupted timestamp data',
        technicalDetails: 'BigInt conversion error in event timestamps',
        failurePoint: 'parsing',
      };
    }

    // Generic WASM parsing error
    return {
      type: ErrorType.WASM_PARSING_ERROR,
      message: 'Failed to parse binary EVTX file',
      technicalDetails: errorMsg,
      failurePoint: 'parsing',
    };
  };

  // Helper function to categorize XML parser errors
  const categorizeXmlError = (error: unknown, filename: string): FileProcessingError => {
    const errorMsg = error instanceof Error ? error.message : String(error);

    // File read errors
    if (errorMsg.includes('Error reading')) {
      return {
        type: ErrorType.FILE_READ_ERROR,
        message: 'Failed to read file contents',
        technicalDetails: errorMsg,
        failurePoint: 'reading',
      };
    }

    // XML parsing errors
    if (errorMsg.includes('XML parsing') || errorMsg.includes('parsererror')) {
      return {
        type: ErrorType.XML_PARSING_ERROR,
        message: 'XML file is malformed or too large to parse',
        technicalDetails: errorMsg,
        failurePoint: 'parsing',
      };
    }

    // Too large
    if (errorMsg.includes('too large')) {
      return {
        type: ErrorType.FILE_TOO_LARGE,
        message: 'XML file is too large for browser to parse',
        technicalDetails: errorMsg,
        failurePoint: 'parsing',
      };
    }

    return {
      type: ErrorType.XML_PARSING_ERROR,
      message: 'Failed to parse XML file',
      technicalDetails: errorMsg,
      failurePoint: 'parsing',
    };
  };

  // Helper function to aggregate file processing results
  const aggregateResults = (results: FileProcessingResult[]): MultiFileProcessingResults => {
    const successfulFiles = results.filter(r => r.status === 'success');
    const failedFiles = results.filter(r => r.status === 'error');
    const partialFiles = results.filter(r => r.status === 'partial');

    const totalRecordsParsed = successfulFiles.reduce((sum, r) => sum + (r.recordCount || 0), 0);

    return {
      totalFiles: results.length,
      successfulFiles,
      failedFiles,
      partialFiles,
      totalRecordsParsed,
      totalErrors: failedFiles.length + partialFiles.length,
    };
  };

  const handleFiles = useCallback(
    async (files: FileList) => {
      if (files.length === 0) return;

      // If only one file, use the original handler (maintains backward compatibility)
      if (files.length === 1) {
        handleFile(files[0]);
        return;
      }

      setIsProcessing(true);
      setTotalFiles(files.length);
      setCurrentFileIndex(0);
      setChunksProcessed(0);
      setTotalChunks(0);

      const results: FileProcessingResult[] = [];

      // Process each file sequentially with per-file error handling
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        setCurrentFileIndex(i + 1);
        setProcessingStatus(`Processing file ${i + 1} of ${files.length}: ${file.name}`);

        const result: FileProcessingResult = {
          filename: file.name,
          fileSize: file.size,
          status: 'error', // Will be updated on success
        };

        try {
          // Validate file size
          const fileSizeMB = file.size / 1024 / 1024;
          const MAX_FILE_SIZE_MB = 1000;

          if (fileSizeMB > MAX_FILE_SIZE_MB) {
            result.error = {
              type: ErrorType.FILE_TOO_LARGE,
              message: `File exceeds maximum size of ${MAX_FILE_SIZE_MB} MB`,
              technicalDetails: `File size: ${fileSizeMB.toFixed(1)} MB`,
              failurePoint: 'validation',
            };
            results.push(result);
            continue;
          }

          // Check if binary EVTX
          const isBinary = await isBinaryEVTX(file);

          if (isBinary) {
            // Binary EVTX path
            setProcessingStatus(`[${i + 1}/${files.length}] Parsing binary EVTX: ${file.name}`);

            try {
              const entries = await parseBinaryEVTXToEntries(
                file,
                (processed, total) => {
                  const totalDisplay = total ? total.toLocaleString() : 'unknown';
                  const percentage = total > 0 ? ` (${Math.round((processed / total) * 100)}%)` : '';
                  setProcessingStatus(
                    `[${i + 1}/${files.length}] ${file.name}: ${processed.toLocaleString()} / ${totalDisplay} records${percentage}`
                  );
                },
                file.name
              );

              const parsedData: ParsedData = {
                entries,
                format: 'evtx',
                totalLines: entries.length,
                parsedLines: entries.length,
                sourceFiles: [file.name],
              };

              result.status = 'success';
              result.parsedData = parsedData;
              result.recordCount = entries.length;
            } catch (parseError) {
              // Categorize WASM parsing errors
              result.error = categorizeWasmError(parseError, file.name);
            }
          } else {
            // XML path
            const CHUNK_SIZE = 10 * 1024 * 1024;
            const fileChunks = Math.ceil(file.size / CHUNK_SIZE);
            setTotalChunks(fileChunks);
            setProcessingStatus(`[${i + 1}/${files.length}] Reading ${file.name}...`);

            try {
              const xmlContent = await new Promise<string>((resolve, reject) => {
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

              // Parse XML
              setProcessingStatus(`[${i + 1}/${files.length}] Parsing events from ${file.name}...`);
              const parsedData = parseLogFile(
                xmlContent,
                (processed, total) => {
                  setProcessingStatus(
                    `[${i + 1}/${files.length}] ${file.name}: ${processed.toLocaleString()} / ${total.toLocaleString()} events`
                  );
                },
                file.name
              );

              result.status = 'success';
              result.parsedData = parsedData;
              result.recordCount = parsedData.entries.length;
            } catch (xmlError) {
              // Categorize XML parsing errors
              result.error = categorizeXmlError(xmlError, file.name);
            }
          }
        } catch (error) {
          // Catch-all for unexpected errors
          result.error = {
            type: ErrorType.UNKNOWN_ERROR,
            message: 'An unexpected error occurred while processing this file',
            technicalDetails: error instanceof Error ? error.message : String(error),
            failurePoint: 'reading',
          };
        }

        results.push(result);
        setChunksProcessed(0);
        setTotalChunks(0);
      }

      // Processing complete - aggregate results
      const aggregatedResults = aggregateResults(results);

      // Show results modal
      setIsProcessing(false);
      setShowProcessingResults(true);
      setProcessingResults(aggregatedResults);
    },
    [onFileLoaded, handleFile, categorizeWasmError, categorizeXmlError, aggregateResults]
  );

  const handleSampleSelect = useCallback(
    async (url: string, filename: string) => {
      setShowSampleSelector(false);
      setIsProcessing(true);
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

        // Process the file using memory-optimized direct conversion
        setProcessingStatus('Parsing sample EVTX file...');
        const entries = await parseBinaryEVTXToEntries(
          file,
          (processed, total) => {
            const totalDisplay = total ? total.toLocaleString() : 'unknown';
            const percentage = total > 0 ? ` (${Math.round((processed / total) * 100)}%)` : '';
            setProcessingStatus(`${processed.toLocaleString()} / ${totalDisplay} records${percentage}`);
          },
          filename
        );

        const parsedData: ParsedData = {
          entries,
          format: 'evtx',
          totalLines: entries.length,
          parsedLines: entries.length,
          sourceFiles: [filename],
        };

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
            <p className="info-note">💡 File size limit: 1GB per file</p>
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

      {showProcessingResults && processingResults && (
        <FileProcessingResultsModal
          results={processingResults}
          onProceed={(mergedData) => {
            setShowProcessingResults(false);
            setProcessingResults(null);
            setCurrentFileIndex(0);
            setTotalFiles(0);
            onFileLoaded(mergedData, processingResults.successfulFiles.map(f => f.filename).join(', '));
          }}
          onCancel={() => {
            setShowProcessingResults(false);
            setProcessingResults(null);
            setCurrentFileIndex(0);
            setTotalFiles(0);
          }}
        />
      )}
    </div>
  );
}
