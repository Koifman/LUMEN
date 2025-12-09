import { useState } from 'react';
import { MultiFileProcessingResults, FileProcessingResult, ErrorType } from '../types/fileProcessing';
import { ParsedData } from '../types';
import './FileProcessingResultsModal.css';

interface FileProcessingResultsModalProps {
  results: MultiFileProcessingResults;
  onProceed: (mergedData: ParsedData) => void;
  onCancel: () => void;
}

export function FileProcessingResultsModal({
  results,
  onProceed,
  onCancel,
}: FileProcessingResultsModalProps) {
  const [expandedErrors, setExpandedErrors] = useState<Set<string>>(new Set());

  const toggleErrorDetails = (filename: string) => {
    const newExpanded = new Set(expandedErrors);
    if (newExpanded.has(filename)) {
      newExpanded.delete(filename);
    } else {
      newExpanded.add(filename);
    }
    setExpandedErrors(newExpanded);
  };

  const handleProceed = () => {
    // Merge all successful file data
    const allEntries = results.successfulFiles.flatMap(f => f.parsedData?.entries || []);
    const allFilenames = results.successfulFiles.map(f => f.filename);

    const mergedData: ParsedData = {
      entries: allEntries,
      format: 'evtx',
      totalLines: allEntries.length,
      parsedLines: allEntries.length,
      sourceFiles: allFilenames,
    };

    onProceed(mergedData);
  };

  const allFilesSucceeded = results.failedFiles.length === 0 && results.partialFiles.length === 0;
  const someFilesSucceeded = results.successfulFiles.length > 0;
  const allFilesFailed = results.successfulFiles.length === 0;

  return (
    <div className="file-results-modal-overlay" onClick={onCancel}>
      <div className="file-results-modal" onClick={e => e.stopPropagation()}>
        {/* Header */}
        <div className="file-results-header">
          <div className="file-results-title-section">
            <h2 className="file-results-title">
              {allFilesSucceeded && '✓ All Files Processed Successfully'}
              {someFilesSucceeded && !allFilesSucceeded && '⚠ Partial Success'}
              {allFilesFailed && '✗ Processing Failed'}
            </h2>
            <span className="file-results-subtitle">
              {results.successfulFiles.length} of {results.totalFiles} files processed successfully
            </span>
          </div>
          <button className="file-results-close" onClick={onCancel} aria-label="Close">
            ✕
          </button>
        </div>

        {/* Summary Stats */}
        <div className="file-results-summary">
          <div className="summary-stat success">
            <div className="stat-value">{results.successfulFiles.length}</div>
            <div className="stat-label">Successful</div>
          </div>
          <div className="summary-stat error">
            <div className="stat-value">{results.failedFiles.length}</div>
            <div className="stat-label">Failed</div>
          </div>
          <div className="summary-stat records">
            <div className="stat-value">{results.totalRecordsParsed.toLocaleString()}</div>
            <div className="stat-label">Total Records</div>
          </div>
        </div>

        {/* Results Table */}
        <div className="file-results-content">
          <table className="file-results-table">
            <thead>
              <tr>
                <th className="col-status">Status</th>
                <th className="col-filename">Filename</th>
                <th className="col-size">Size</th>
                <th className="col-records">Records</th>
                <th className="col-details">Details</th>
              </tr>
            </thead>
            <tbody>
              {/* Successful files */}
              {results.successfulFiles.map(file => (
                <tr key={file.filename} className="file-row success">
                  <td className="col-status">
                    <span className="status-icon success" title="Success">✓</span>
                  </td>
                  <td className="col-filename" title={file.filename}>
                    {file.filename}
                  </td>
                  <td className="col-size">{formatFileSize(file.fileSize)}</td>
                  <td className="col-records">{file.recordCount?.toLocaleString() || 0}</td>
                  <td className="col-details">
                    <span className="success-message">Parsed successfully</span>
                  </td>
                </tr>
              ))}

              {/* Failed files */}
              {results.failedFiles.map(file => (
                <tr key={file.filename} className="file-row error">
                  <td className="col-status">
                    <span className="status-icon error" title="Failed">✗</span>
                  </td>
                  <td className="col-filename" title={file.filename}>
                    {file.filename}
                  </td>
                  <td className="col-size">{formatFileSize(file.fileSize)}</td>
                  <td className="col-records">-</td>
                  <td className="col-details">
                    <div className="error-details-cell">
                      <div className="error-message">
                        {getErrorIcon(file.error!.type)} {file.error!.message}
                      </div>
                      <button
                        className="expand-details-btn"
                        onClick={() => toggleErrorDetails(file.filename)}
                      >
                        {expandedErrors.has(file.filename) ? 'Hide Details' : 'Show Details'}
                      </button>
                      {expandedErrors.has(file.filename) && (
                        <div className="expanded-error-details">
                          <div className="error-detail-row">
                            <span className="error-detail-label">Error Type:</span>
                            <span className="error-detail-value">{file.error!.type}</span>
                          </div>
                          {file.error!.failurePoint && (
                            <div className="error-detail-row">
                              <span className="error-detail-label">Failure Point:</span>
                              <span className="error-detail-value">{file.error!.failurePoint}</span>
                            </div>
                          )}
                          {file.error!.technicalDetails && (
                            <div className="error-detail-row technical">
                              <span className="error-detail-label">Technical Details:</span>
                              <pre className="error-detail-value">{file.error!.technicalDetails}</pre>
                            </div>
                          )}
                          {getErrorRecommendation(file.error!.type) && (
                            <div className="error-recommendation">
                              💡 {getErrorRecommendation(file.error!.type)}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Footer Actions */}
        <div className="file-results-footer">
          {someFilesSucceeded ? (
            <>
              <button className="file-results-button secondary" onClick={onCancel}>
                Cancel
              </button>
              <button className="file-results-button primary" onClick={handleProceed}>
                Proceed with {results.successfulFiles.length} successful file
                {results.successfulFiles.length !== 1 ? 's' : ''} ({results.totalRecordsParsed.toLocaleString()}{' '}
                records)
              </button>
            </>
          ) : (
            <button className="file-results-button secondary" onClick={onCancel}>
              Close
            </button>
          )}
        </div>

        {results.failedFiles.length > 0 && (
          <div className="file-results-help">
            💡 Failed files can be re-uploaded after addressing the errors shown above
          </div>
        )}
      </div>
    </div>
  );
}

// Helper functions
function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function getErrorIcon(errorType: ErrorType): string {
  switch (errorType) {
    case ErrorType.FILE_TOO_LARGE:
      return '📦';
    case ErrorType.INVALID_FORMAT:
      return '📄';
    case ErrorType.CORRUPTED_FILE:
      return '🔧';
    case ErrorType.WASM_PARSING_ERROR:
    case ErrorType.XML_PARSING_ERROR:
      return '⚠️';
    case ErrorType.NO_RECORDS_FOUND:
      return '📭';
    case ErrorType.FILE_READ_ERROR:
    case ErrorType.WASM_INITIALIZATION_ERROR:
    case ErrorType.MEMORY_ERROR:
      return '💻';
    default:
      return '❓';
  }
}

function getErrorRecommendation(errorType: ErrorType): string | null {
  switch (errorType) {
    case ErrorType.FILE_TOO_LARGE:
      return 'Try filtering events in Event Viewer before exporting, or split the file into smaller chunks.';
    case ErrorType.INVALID_FORMAT:
      return 'Ensure the file is a valid .evtx file or XML export from Windows Event Viewer.';
    case ErrorType.CORRUPTED_FILE:
      return 'The file may be corrupted. Try re-exporting from the source system.';
    case ErrorType.XML_PARSING_ERROR:
      return 'Use the binary .evtx file instead of XML export, or reduce the file size.';
    case ErrorType.NO_RECORDS_FOUND:
      return 'The file appears empty or all records failed to parse. Verify the file contains valid events.';
    case ErrorType.WASM_INITIALIZATION_ERROR:
      return 'Try refreshing the page. This may be a browser compatibility issue.';
    case ErrorType.MEMORY_ERROR:
      return 'Your browser ran out of memory. Close other tabs or use a smaller file.';
    case ErrorType.FILE_READ_ERROR:
      return 'The file could not be read. It may be locked or corrupted.';
    default:
      return null;
  }
}
