export interface LogEntry {
  timestamp: Date;
  ip: string;
  method: string;
  path: string;
  statusCode: number;
  size: number;
  userAgent?: string;
  rawLine: string;
  // EVTX-specific fields
  eventId?: number;
  level?: string;
  source?: string;
  computer?: string;
  message?: string;
  // Multi-file support
  sourceFile?: string;
}

export interface ParsedData {
  entries: LogEntry[];
  format: 'evtx' | 'unknown';
  totalLines: number;
  parsedLines: number;
  sourceFiles?: string[];
}

export type LLMProvider =
  | 'openai'
  | 'anthropic'
  | 'google'
  | 'ollama';

export interface ChartDataPoint {
  time: string;
  count: number;
}

export interface StatusCodeData {
  code: string;
  count: number;
}

export interface IPData {
  ip: string;
  count: number;
}
