/**
 * Multi-file EVTX Processing Types
 *
 * Type definitions for enhanced error handling during multi-file uploads
 */

import { ParsedData } from '../types';

/**
 * Error types with different verbosity levels
 */
export enum ErrorType {
  // Validation errors (high verbosity - user can fix)
  FILE_TOO_LARGE = 'FILE_TOO_LARGE',
  INVALID_FORMAT = 'INVALID_FORMAT',
  CORRUPTED_FILE = 'CORRUPTED_FILE',

  // Parsing errors (medium verbosity - partial recovery possible)
  WASM_PARSING_ERROR = 'WASM_PARSING_ERROR',
  XML_PARSING_ERROR = 'XML_PARSING_ERROR',
  NO_RECORDS_FOUND = 'NO_RECORDS_FOUND',

  // Technical errors (low verbosity - system/browser issue)
  FILE_READ_ERROR = 'FILE_READ_ERROR',
  WASM_INITIALIZATION_ERROR = 'WASM_INITIALIZATION_ERROR',
  MEMORY_ERROR = 'MEMORY_ERROR',

  // Unknown
  UNKNOWN_ERROR = 'UNKNOWN_ERROR',
}

/**
 * Categorized error information for a file
 */
export interface FileProcessingError {
  // Error categorization
  type: ErrorType;

  // Error messages
  message: string;
  technicalDetails?: string;

  // Context
  failurePoint?: 'validation' | 'reading' | 'parsing' | 'conversion' | 'extraction';
  partialRecordsParsed?: number;
  totalChunksAttempted?: number;
  failedChunks?: number;
}

/**
 * Represents the result of processing a single file
 */
export interface FileProcessingResult {
  // File identification
  filename: string;
  fileSize: number;

  // Status
  status: 'success' | 'error' | 'partial';

  // Success data
  parsedData?: ParsedData;
  recordCount?: number;

  // Error information
  error?: FileProcessingError;
}

/**
 * Aggregated results from multi-file processing
 */
export interface MultiFileProcessingResults {
  totalFiles: number;
  successfulFiles: FileProcessingResult[];
  failedFiles: FileProcessingResult[];
  partialFiles: FileProcessingResult[];

  // Summary stats
  totalRecordsParsed: number;
  totalErrors: number;
}
