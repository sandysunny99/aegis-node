import { useCallback, useRef, useState } from 'react';
import Icon from '../ui/Icon';

const ACCEPTED_EXTS = ['.csv', '.json', '.jsonl', '.parquet', '.xlsx', '.txt'];
const FORMATS = ACCEPTED_EXTS.map((e) => e.slice(1).toUpperCase()).join(', ');

function formatBytes(b) {
  if (!b) return '0 B';
  if (b < 1024) return `${b} B`;
  if (b < 1024 ** 2) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1024 ** 2).toFixed(1)} MB`;
}

export default function UploadZone({ file, onFile, onClear, uploadProgress }) {
  const [dragging, setDragging] = useState(false);
  const [rejected, setRejected] = useState('');
  const inputRef = useRef(null);

  const handleFiles = useCallback((files) => {
    if (!files || files.length === 0) return;
    const f = files[0];
    const ext = `.${f.name.split('.').pop().toLowerCase()}`;
    if (!ACCEPTED_EXTS.includes(ext)) {
      setRejected(`${f.name} is not a supported format. Choose a ${FORMATS} file.`);
      return;
    }
    setRejected('');
    onFile(f);
  }, [onFile]);

  const openPicker = () => inputRef.current?.click();

  if (file) {
    const uploading = uploadProgress !== undefined && uploadProgress !== null;
    return (
      <div className="stack-sm">
        <div className="file-pill">
          <Icon name="FileText" size={20} />
          <span className="file-pill-name">{file.name}</span>
          <span className="file-pill-size">{formatBytes(file.size)}</span>
          {!uploading && (
            <button type="button" className="icon-btn" onClick={onClear} aria-label={`Remove ${file.name}`}>
              <Icon name="X" size={18} />
            </button>
          )}
        </div>
        {uploading && (
          <div className="progress">
            <div className="progress__label">
              <span>Uploading</span>
              <span className="mono">{uploadProgress}%</span>
            </div>
            <div className="progress__track" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={uploadProgress} aria-label="Upload progress">
              <div className="progress__bar" style={{ width: `${uploadProgress}%` }} />
            </div>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="stack-sm">
      <div
        className={`upload-zone${dragging ? ' drag-over' : ''}`}
        onDrop={(e) => { e.preventDefault(); setDragging(false); handleFiles(e.dataTransfer.files); }}
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onClick={openPicker}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openPicker(); }
        }}
        role="button"
        tabIndex={0}
        aria-describedby="upload-hint"
        id="upload-dropzone"
      >
        <input
          ref={inputRef}
          type="file"
          accept={ACCEPTED_EXTS.join(',')}
          onChange={(e) => handleFiles(e.target.files)}
          hidden
          id="file-input"
        />
        <Icon name="Upload" size={28} className="upload-icon" />
        <p className="upload-label">{dragging ? 'Drop the dataset to select it' : 'Drop a dataset here, or choose a file'}</p>
        <p className="upload-hint" id="upload-hint">{FORMATS}, up to the server's size limit</p>
      </div>
      {rejected && (
        <div className="error-banner" role="alert">
          <Icon name="CircleAlert" />
          <span>{rejected}</span>
        </div>
      )}
    </div>
  );
}
