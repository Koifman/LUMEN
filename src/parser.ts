import { LogEntry, ParsedData } from './types';

/**
 * Detect log format by sampling first few lines
 */
function detectFormat(sample: string): 'evtx' | 'unknown' {
  // Check for XML/EVTX format
  if (sample.trim().startsWith('<?xml') || sample.includes('<Events>') || sample.includes('<Event ')) {
    return 'evtx';
  }

  return 'unknown';
}

/**
 * Parse Windows EVTX (exported as XML)
 * Handles exported Event Logs from Windows Event Viewer
 */
function parseEVTXXML(
  content: string,
  onProgress?: (processed: number, total: number) => void,
  filename?: string
): LogEntry[] {
  const entries: LogEntry[] = [];

  console.log(`Starting XML parsing... Content size: ${(content.length / 1024 / 1024).toFixed(2)} MB`);

  const parser = new DOMParser();
  const xmlDoc = parser.parseFromString(content, 'text/xml');

  // Check for parsing errors
  const parserError = xmlDoc.querySelector('parsererror');
  if (parserError) {
    const errorText = parserError.textContent || '';
    console.error('XML parsing error:', errorText);

    // If it's a "Premature end of data" error, the file might be truncated or too large
    // Try to extract what we can parse up to the error
    if (errorText.includes('Premature end of data') || errorText.includes('premature')) {
      console.warn('XML appears to be truncated or incomplete. Attempting to extract parseable events...');

      // DOMParser may have parsed partial content before the error
      // Try to get Event elements that were successfully parsed
      const partialEvents = xmlDoc.querySelectorAll('Event');
      if (partialEvents.length > 0) {
        console.log(`Recovered ${partialEvents.length} events from partial XML`);
        // Continue processing with what we have
      } else {
        throw new Error(
          `XML file is too large or corrupted. The browser cannot parse this 346MB XML file.\n\n` +
          `Recommendations:\n` +
          `1. Use the binary .evtx file instead (not the XML export)\n` +
          `2. Split the XML into smaller files\n` +
          `3. Filter events in Event Viewer before exporting\n\n` +
          `Error: ${errorText}`
        );
      }
    } else {
      throw new Error(`XML parsing failed: ${errorText}`);
    }
  }

  const events = xmlDoc.querySelectorAll('Event');
  const totalEvents = events.length;

  console.log(`Found ${totalEvents} Event elements in XML`);

  // Report initial progress
  if (onProgress) {
    onProgress(0, totalEvents);
  }

  events.forEach((event, index) => {
    try {
      // Extract System data
      const system = event.querySelector('System');
      if (!system) return;

      const eventIdElem = system.querySelector('EventID');
      const levelElem = system.querySelector('Level');
      const timeCreatedElem = system.querySelector('TimeCreated');
      const computerElem = system.querySelector('Computer');
      const providerElem = system.querySelector('Provider');

      // Extract EventData
      const eventData = event.querySelector('EventData');
      const eventDataMap: Record<string, string> = {};

      // Try to extract IP address from Data elements
      let ip = 'N/A';
      const dataElements = event.querySelectorAll('Data');
      dataElements.forEach((data) => {
        const name = data.getAttribute('Name');
        const value = data.textContent || '';
        if (!name) return;

        // Capture for downstream structured access
        eventDataMap[name] = value;

        // Look for common IP field names
        if (name.includes('IpAddress') || name.includes('IPAddress') || name.includes('SourceAddress') || name.includes('ClientIP')) {
          ip = value;
        }
      });

      // Extract message or data content
      let message = '';
      if (eventData) {
        const dataTexts: string[] = [];
        for (const [name, value] of Object.entries(eventDataMap)) {
          if (value) {
            dataTexts.push(`${name}=${value}`);
          }
        }
        message = dataTexts.join(', ');
      }

      const eventId = eventIdElem ? parseInt(eventIdElem.textContent || '0', 10) : 0;
      const level = levelElem ? levelElem.textContent || 'Information' : 'Information';
      const levelName = getLevelName(level);

      // Parse timestamp with validation
      let timestamp = new Date();
      if (timeCreatedElem) {
        const systemTime = timeCreatedElem.getAttribute('SystemTime');
        if (systemTime) {
          const parsedDate = new Date(systemTime);
          // Only use parsed date if it's valid
          if (!isNaN(parsedDate.getTime())) {
            timestamp = parsedDate;
          }
        }
      }

      const computer = computerElem ? computerElem.textContent || 'Unknown' : 'Unknown';
      const source = providerElem ? providerElem.getAttribute('Name') || 'Unknown' : 'Unknown';

      // For EVTX logs, if no IP was found, use the computer name
      if (ip === 'N/A' && computer !== 'Unknown') {
        ip = computer;
      }

      // Map to LogEntry format
      entries.push({
        timestamp,
        ip,
        method: source.substring(0, 20), // Use source as "method" for display
        path: `Event ${eventId}`,
        statusCode: eventId,
        size: 0,
        rawLine: new XMLSerializer().serializeToString(event),
        eventId,
        level: levelName,
        source,
        computer,
        message,
        eventData: Object.keys(eventDataMap).length ? eventDataMap : undefined,
        sourceFile: filename,
      });

      // Report progress every 100 events to avoid too many updates
      if (onProgress && (index + 1) % 100 === 0) {
        onProgress(index + 1, totalEvents);
      }
    } catch (err) {
      // Skip events that fail to parse
    }
  });

  // Report final progress
  if (onProgress) {
    onProgress(totalEvents, totalEvents);
  }

  return entries;
}

/**
 * Convert Windows Event Level to readable name
 */
function getLevelName(level: string): string {
  const levelMap: Record<string, string> = {
    '0': 'LogAlways',
    '1': 'Critical',
    '2': 'Error',
    '3': 'Warning',
    '4': 'Information',
    '5': 'Verbose',
  };
  return levelMap[level] || level;
}

/**
 * Main parsing function - EVTX XML only
 */
export function parseLogFile(
  content: string,
  onProgress?: (processed: number, total: number) => void,
  filename?: string
): ParsedData {
  const format = detectFormat(content);
  let entries: LogEntry[] = [];
  let totalLines = 0;

  if (format === 'evtx') {
    // Parse XML-formatted EVTX
    entries = parseEVTXXML(content, onProgress, filename);
    totalLines = entries.length;
  } else {
    // Unknown format - try to parse as EVTX anyway
    entries = parseEVTXXML(content, onProgress, filename);
    totalLines = entries.length;
  }

  return {
    entries,
    format: entries.length > 0 ? 'evtx' : 'unknown',
    totalLines,
    parsedLines: entries.length,
    sourceFiles: filename ? [filename] : undefined,
  };
}
