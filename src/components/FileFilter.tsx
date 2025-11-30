import { useMemo } from 'react';
import './FileFilter.css';

interface FileFilterProps {
  sourceFiles?: string[];
  selectedFile: string | null;
  onFileSelect: (file: string | null) => void;
}

export default function FileFilter({ sourceFiles, selectedFile, onFileSelect }: FileFilterProps) {
  const showFilter = useMemo(() => {
    return sourceFiles && sourceFiles.length > 1;
  }, [sourceFiles]);

  if (!showFilter) {
    return null;
  }

  return (
    <div className="file-filter">
      <label htmlFor="file-selector">Filter by file:</label>
      <select
        id="file-selector"
        value={selectedFile || 'all'}
        onChange={(e) => onFileSelect(e.target.value === 'all' ? null : e.target.value)}
      >
        <option value="all">All files ({sourceFiles.length})</option>
        {sourceFiles.map((file, index) => (
          <option key={index} value={file}>
            {file}
          </option>
        ))}
      </select>
    </div>
  );
}
