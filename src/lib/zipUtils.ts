import JSZip from 'jszip';

/**
 * Checks if a file is a ZIP archive by examining its magic signature
 * ZIP files start with "PK\x03\x04" (0x504B0304)
 */
export async function isZipFile(file: File): Promise<boolean> {
  try {
    const buffer = await file.slice(0, 4).arrayBuffer();
    const bytes = new Uint8Array(buffer);

    // Check for ZIP magic signature: PK\x03\x04
    return bytes[0] === 0x50 && bytes[1] === 0x4B &&
           bytes[2] === 0x03 && bytes[3] === 0x04;
  } catch (error) {
    console.error('Error checking ZIP signature:', error);
    return false;
  }
}

export interface ExtractedFile {
  name: string;
  file: File;
  originalPath: string; // Path within the ZIP archive
}

export interface ZipExtractionResult {
  success: boolean;
  files: ExtractedFile[];
  error?: string;
  zipName: string;
}

/**
 * Extracts EVTX and XML files from a ZIP archive
 * Supports nested directories within the ZIP
 *
 * @param zipFile - The ZIP file to extract
 * @param maxFileSizeMB - Maximum size per extracted file in MB (default: 1000)
 * @returns Promise with extraction results
 */
export async function extractFilesFromZip(
  zipFile: File,
  maxFileSizeMB: number = 1000
): Promise<ZipExtractionResult> {
  const result: ZipExtractionResult = {
    success: false,
    files: [],
    zipName: zipFile.name,
  };

  try {
    const zip = await JSZip.loadAsync(zipFile);
    const extractedFiles: ExtractedFile[] = [];

    // Iterate through all files in the ZIP
    for (const [relativePath, zipEntry] of Object.entries(zip.files)) {
      // Skip directories
      if (zipEntry.dir) {
        continue;
      }

      // Only process .evtx and .xml files
      const lowerPath = relativePath.toLowerCase();
      if (!lowerPath.endsWith('.evtx') && !lowerPath.endsWith('.xml')) {
        continue;
      }

      // Get the file as a Blob
      const blob = await zipEntry.async('blob');

      // Check file size
      const fileSizeMB = blob.size / (1024 * 1024);
      if (fileSizeMB > maxFileSizeMB) {
        console.warn(`Skipping ${relativePath}: too large (${fileSizeMB.toFixed(1)} MB)`);
        continue;
      }

      // Extract just the filename from the path
      const fileName = relativePath.split('/').pop() || relativePath;

      // Create a File object from the Blob
      // Use the full path in the ZIP as part of the source tracking
      const file = new File([blob], fileName, { type: blob.type });

      extractedFiles.push({
        name: fileName,
        file: file,
        originalPath: relativePath,
      });
    }

    if (extractedFiles.length === 0) {
      result.error = 'No EVTX or XML files found in ZIP archive';
      return result;
    }

    result.success = true;
    result.files = extractedFiles;
    return result;

  } catch (error) {
    result.error = error instanceof Error ? error.message : 'Failed to extract ZIP archive';
    console.error('ZIP extraction error:', error);
    return result;
  }
}
