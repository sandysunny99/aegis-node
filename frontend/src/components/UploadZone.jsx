import React, { useCallback, useRef, useState } from 'react';

const ACCEPTED_EXTS = ['.csv', '.json', '.jsonl', '.parquet', '.xlsx', '.txt'];
const ACCEPTED_MIME = [
  'text/csv', 'application/json', 'application/octet-stream',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'text/plain',
];

function formatBytes(b) {
  if (!b) return '0 B';
  if (b < 1024) return `${b} B`;
  if (b < 1024 ** 2) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1024 ** 2).toFixed(1)} MB`;
}

export default function UploadZone({ file, onFile, onClear, uploadProgress }) {
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef(null);

  const handleFiles = useCallback((files) => {
    if (!files || files.length === 0) return;
    const f = files[0];
    const ext = '.' + f.name.split('.').pop().toLowerCase();
    if (!ACCEPTED_EXTS.includes(ext)) {
      alert(`Unsupported file type: ${ext}\nAccepted: ${ACCEPTED_EXTS.join(', ')}`);
      return;
    }
    onFile(f);
  }, [onFile]);

  const onDrop = useCallback((e) => {
    e.preventDefault(); setDragging(false);
    handleFiles(e.dataTransfer.files);
  }, [handleFiles]);

  const onDragOver = (e) => { e.preventDefault(); setDragging(true); };
  const onDragLeave = () => setDragging(false);
  const onInputChange = (e) => handleFiles(e.target.files);

  if (file) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        <div className="file-pill fade-in">
          <span className="file-pill-icon">{getFileIcon(file.name)}</span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="file-pill-name" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {file.name}
            </div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-3)', marginTop: '2px' }}>
              {formatBytes(file.size)} · {file.name.split('.').pop().toUpperCase()}
            </div>
          </div>
          {!uploadProgress && (
            <button className="file-pill-remove" onClick={onClear} title="Remove file">✕</button>
          )}
        </div>

        {uploadProgress !== undefined && uploadProgress !== null && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: 'var(--text-3)' }}>
              <span>Uploading…</span>
              <span style={{ fontFamily: 'var(--mono)', color: 'var(--cyan)' }}>{uploadProgress}%</span>
            </div>
            <div style={{
              height: '4px', background: 'var(--bg-0)', borderRadius: '9999px', overflow: 'hidden',
            }}>
              <div style={{
                height: '100%', borderRadius: '9999px',
                background: 'linear-gradient(90deg, var(--cyan), var(--blue))',
                width: `${uploadProgress}%`,
                transition: 'width 0.2s ease',
                boxShadow: '0 0 8px var(--cyan)',
              }} />
            </div>
          </div>
        )}
      </div>
    );
  }

  return (
    <div
      className={`upload-zone${dragging ? ' drag-over' : ''}`}
      onDrop={onDrop}
      onDragOver={onDragOver}
      onDragLeave={onDragLeave}
      onClick={() => inputRef.current?.click()}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => e.key === 'Enter' && inputRef.current?.click()}
      id="upload-dropzone"
    >
      <input
        ref={inputRef}
        type="file"
        accept={ACCEPTED_EXTS.join(',')}
        onChange={onInputChange}
        style={{ display: 'none' }}
        id="file-input"
      />
      <div className="upload-icon">📁</div>
      <div className="upload-label">
        {dragging ? 'Drop your dataset here' : 'Drag & drop your dataset'}
      </div>
      <div className="upload-hint">
        or <span>click to browse</span> · Supports{' '}
        {ACCEPTED_EXTS.map(e => e.slice(1).toUpperCase()).join(', ')}
      </div>
      <div style={{
        display: 'flex', gap: '0.5rem', justifyContent: 'center',
        marginTop: '1.25rem', flexWrap: 'wrap',
      }}>
        {ACCEPTED_EXTS.map(ext => (
          <span key={ext} style={{
            padding: '0.2rem 0.6rem',
            background: 'rgba(59,130,246,0.08)',
            border: '1px solid rgba(59,130,246,0.2)',
            borderRadius: '9999px',
            fontSize: '0.7rem',
            color: 'var(--blue)',
            fontFamily: 'var(--mono)',
            fontWeight: 600,
          }}>
            {ext.slice(1).toUpperCase()}
          </span>
        ))}
      </div>
    </div>
  );
}

function getFileIcon(name) {
  const ext = name.split('.').pop().toLowerCase();
  const icons = { csv: '📊', json: '📋', jsonl: '📋', parquet: '🗜️', xlsx: '📗', txt: '📄' };
  return icons[ext] || '📁';
}
