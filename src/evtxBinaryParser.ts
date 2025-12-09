/**
 * Binary EVTX Parser
 *
 * Parses Windows Event Log binary format (.evtx files)
 * Based on Microsoft's EVTX specification
 *
 * Note: This is a simplified parser that extracts XML from binary chunks
 * The EVTX format embeds XML records in a binary container
 */

export interface EVTXHeader {
  signature: string;
  oldestChunk: number;
  currentChunkNumber: number;
  nextRecordNumber: number;
  headerSize: number;
  minorVersion: number;
  majorVersion: number;
  headerBlockSize: number;
  numberOfChunks: number;
  flags: number;
  checksum: number;
}

/**
 * Read ASCII string from buffer
 */
function readASCIIString(buffer: DataView, offset: number, length: number): string {
  const chars: number[] = [];
  for (let i = 0; i < length; i++) {
    chars.push(buffer.getUint8(offset + i));
  }
  return String.fromCharCode(...chars);
}

/**
 * Parse EVTX file header
 */
function parseEVTXHeader(buffer: ArrayBuffer): EVTXHeader | null {
  if (buffer.byteLength < 128) {
    return null;
  }

  const view = new DataView(buffer, 0, 128);

  // Read magic signature "ElfFile\0"
  const signature = readASCIIString(view, 0, 8);

  if (signature !== 'ElfFile\0') {
    return null;
  }

  return {
    signature,
    oldestChunk: view.getBigUint64(8, true) as unknown as number,
    currentChunkNumber: view.getBigUint64(16, true) as unknown as number,
    nextRecordNumber: view.getBigUint64(24, true) as unknown as number,
    headerSize: view.getUint32(32, true),
    minorVersion: view.getUint16(36, true),
    majorVersion: view.getUint16(38, true),
    headerBlockSize: view.getUint16(40, true),
    numberOfChunks: view.getUint16(42, true),
    flags: view.getUint32(120, true),
    checksum: view.getUint32(124, true),
  };
}

/**
 * Alternative: Scan for XML in both UTF-16LE and UTF-8
 * Improved with multiple regex patterns and better debugging
 */
function extractXMLAdvanced(buffer: ArrayBuffer): string {
  const uint8Array = new Uint8Array(buffer);
  let allEvents: string[] = [];

  // Try UTF-16LE first (most common in EVTX)
  const utf16Decoder = new TextDecoder('utf-16le', { fatal: false });
  const utf8Decoder = new TextDecoder('utf-8', { fatal: false });

  const chunkSize = 65536;
  const headerSize = 4096;

  for (let offset = headerSize; offset < buffer.byteLength; offset += chunkSize) {
    const end = Math.min(offset + chunkSize, buffer.byteLength);
    const chunk = uint8Array.slice(offset, end);

    // Try both encodings
    for (const decoder of [utf16Decoder, utf8Decoder]) {
      try {
        const text = decoder.decode(chunk);

        // Try multiple regex patterns (EVTX files can have variations)
        const patterns = [
          // Standard Event with xmlns
          /<Event\s+xmlns=["']http:\/\/schemas\.microsoft\.com\/win\/2004\/08\/events\/event["'][^>]*>[\s\S]*?<\/Event>/gi,
          // Event without xmlns attribute
          /<Event[^>]*>[\s\S]*?<\/Event>/gi,
        ];

        for (const regex of patterns) {
          const matches = Array.from(text.matchAll(regex));

          for (const match of matches) {
            // Clean up the XML (remove null bytes and control characters)
            let cleanXML = match[0]
              .replace(/\0/g, '')
              .replace(/[\x00-\x08\x0B-\x0C\x0E-\x1F]/g, '')
              .trim();

            // Ensure it has System element (required for valid Event)
            if (cleanXML.includes('<System') && cleanXML.includes('</Event>')) {
              // Add xmlns if missing
              if (!cleanXML.includes('xmlns=')) {
                cleanXML = cleanXML.replace(
                  /<Event/,
                  '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"'
                );
              }
              allEvents.push(cleanXML);
            }
          }
        }
      } catch (e) {
        // Skip on decode error
        continue;
      }
    }
  }

  // Remove duplicates (chunks may overlap)
  const uniqueEvents = [...new Set(allEvents)];

  if (uniqueEvents.length > 0) {
    return `<?xml version="1.0" encoding="utf-8"?>\n<Events>\n${uniqueEvents.join('\n')}\n</Events>`;
  }

  return '';
}

/**
 * Main function to parse binary EVTX file
 */
export async function parseBinaryEVTX(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();

    reader.onload = (e) => {
      const buffer = e.target?.result as ArrayBuffer;

      if (!buffer) {
        reject(new Error('Failed to read file'));
        return;
      }

      // Validate EVTX header
      const header = parseEVTXHeader(buffer);

      if (!header) {
        reject(new Error(
          `Invalid EVTX file format.\n\n` +
          `Expected magic signature: "ElfFile\\0"\n` +
          `This file does not appear to be a valid binary EVTX file.\n\n` +
          `Please ensure you're using:\n` +
          `1. A valid .evtx file from Windows Event Viewer\n` +
          `2. Not a manually edited or corrupted file`
        ));
        return;
      }

      // Extract XML from binary chunks
      const xmlContent = extractXMLAdvanced(buffer);

      if (!xmlContent || xmlContent.trim().length === 0) {
        reject(new Error(
          'No valid Event XML found in EVTX file. ' +
          'This file may use compression or binary templates. ' +
          'Please export to XML from Event Viewer instead.'
        ));
        return;
      }

      resolve(xmlContent);
    };

    reader.onerror = () => {
      reject(new Error('Failed to read EVTX file'));
    };

    reader.readAsArrayBuffer(file);
  });
}

/**
 * Check if a file is binary EVTX format
 */
export async function isBinaryEVTX(file: File): Promise<boolean> {
  return new Promise((resolve) => {
    const reader = new FileReader();

    reader.onload = (e) => {
      const buffer = e.target?.result as ArrayBuffer;
      if (!buffer || buffer.byteLength < 8) {
        resolve(false);
        return;
      }

      const view = new DataView(buffer);
      const signature = readASCIIString(view, 0, 8);

      resolve(signature === 'ElfFile\0');
    };

    reader.onerror = () => resolve(false);

    // Only read first 8 bytes for signature check
    reader.readAsArrayBuffer(file.slice(0, 8));
  });
}
