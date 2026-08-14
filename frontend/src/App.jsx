import React, { useCallback, useEffect, useState } from 'react';
import { healthCheck, scanDataset, uploadDataset } from './api';
import AiSummary from './components/AiSummary';
import FindingsList from './components/FindingsList';
import RemediationCard from './components/RemediationCard';
import RiskMeter from './components/RiskMeter';
import StatusBadge from './components/StatusBadge';
import UploadZone from './components/UploadZone';
import HistoryPage from './pages/HistoryPage';

// ─── Utility ───────────────────────────────────────────────
function formatBytes(b) {
  if (b < 1024) return `${b} B`;
  if (b < 1024 ** 2) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1024 ** 2).toFixed(1)} MB`;
}

// ─── Pipeline Step Row ─────────────────────────────────────
function StepRow({ done, active, label }) {
  const cls = done ? 'done' : active ? 'active' : 'pending';
  const icon = done ? '✔' : active ? <span className="spinner" /> : '○';
  return (
    <div className={`step ${cls}`}>
      <span className="step-icon" style={{ display: 'flex', alignItems: 'center' }}>{icon}</span>
      <span>{label}</span>
    </div>
  );
}

// ─── Tab bar ───────────────────────────────────────────────
function TabBar({ active, onChange }) {
  const tabs = [
    { id: 'scan',    label: '🔍 Scan Dataset' },
    { id: 'history', label: '📋 Scan History'  },
  ];
  return (
    <div style={{
      display: 'flex', gap: '0.25rem', background: 'var(--bg-2)',
      border: '1px solid var(--border)', borderRadius: 'var(--r-md)',
      padding: '0.25rem',
    }}>
      {tabs.map(t => (
        <button
          key={t.id}
          onClick={() => onChange(t.id)}
          id={`tab-${t.id}`}
          style={{
            background: active === t.id ? 'var(--bg-3)' : 'transparent',
            border: active === t.id ? '1px solid var(--border)' : '1px solid transparent',
            borderRadius: 'var(--r-sm)', color: active === t.id ? 'var(--text-1)' : 'var(--text-3)',
            fontFamily: 'var(--font)', fontWeight: 500, fontSize: '0.85rem',
            padding: '0.45rem 1.1rem', cursor: 'pointer',
            transition: 'all 0.15s',
          }}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}

// ─── Health Status Pill ────────────────────────────────────
function HealthStatus({ health }) {
  if (!health) return (
    <div className="header-status">
      <span style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--amber)', display: 'inline-block', boxShadow: '0 0 8px var(--amber)' }} />
      Connecting…
    </div>
  );

  const online = health.status === 'ok';

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '0.875rem' }}>
      {/* API Status */}
      <div className="header-status">
        <span className={online ? 'pulse' : undefined}
          style={!online ? { width: 8, height: 8, borderRadius: '50%', background: 'var(--rose)', boxShadow: '0 0 8px var(--rose)', display: 'inline-block' } : {}} />
        {online ? 'API Online' : 'API Offline'}
      </div>

      {/* ClamAV */}
      <div className="header-status" title={health.clamav_mock ? 'ClamAV: Simulated (rule-based detection active)' : 'ClamAV antivirus daemon status'}>
        <span style={{
          width: 7, height: 7, borderRadius: '50%', display: 'inline-block',
          background: health.clamav_running
            ? (health.clamav_mock ? 'var(--cyan)' : 'var(--emerald)')
            : 'var(--amber)',
          boxShadow: health.clamav_running
            ? (health.clamav_mock ? '0 0 6px var(--cyan)' : '0 0 6px var(--emerald)')
            : '0 0 6px var(--amber)',
        }} />
        {health.clamav_running
          ? (health.clamav_mock ? 'AV: Simulated' : 'ClamAV')
          : 'No AV'}
      </div>


      {/* AI */}
      <div className="header-status" title={`AI provider: ${health.ai_provider ?? 'none'}`}>
        <span style={{
          width: 7, height: 7, borderRadius: '50%', display: 'inline-block',
          background: health.ai_configured ? 'var(--cyan)' : 'var(--text-3)',
          boxShadow: health.ai_configured ? '0 0 6px var(--cyan)' : 'none',
        }} />
        {health.ai_configured ? `AI: ${health.ai_provider ?? 'on'}` : 'AI: off'}
      </div>
    </div>
  );
}

// ─── Scan Page ─────────────────────────────────────────────
function ScanPage() {
  const [file, setFile] = useState(null);
  const [phase, setPhase] = useState('idle');
  const [uploadProgress, setUploadProgress] = useState(null);
  const [uploadResult, setUploadResult] = useState(null);
  const [scanResult, setScanResult] = useState(null);
  const [error, setError] = useState('');

  const reset = useCallback(() => {
    setFile(null); setPhase('idle');
    setUploadProgress(null);
    setUploadResult(null); setScanResult(null); setError('');
  }, []);

  const handleUpload = useCallback(async () => {
    if (!file) return;
    setPhase('uploading'); setError(''); setUploadProgress(0);
    try {
      const r = await uploadDataset(file, (pct) => setUploadProgress(pct));
      setUploadResult(r); setPhase('uploaded'); setUploadProgress(null);
    } catch (e) { setError(e.message); setPhase('error'); setUploadProgress(null); }
  }, [file]);

  const handleScan = useCallback(async () => {
    if (!uploadResult) return;
    setPhase('scanning'); setError('');
    try {
      const r = await scanDataset(uploadResult.dataset_id);
      setScanResult(r); setPhase('done');
    } catch (e) { setError(e.message); setPhase('done'); }
  }, [uploadResult]);

  const isUploading = phase === 'uploading';
  const isScanning  = phase === 'scanning';
  const isDone      = phase === 'done';
  const isError     = phase === 'error';

  return (
    <>
      {/* Upload Card */}
      <div className="card">
        <div className="card-title">Upload Dataset</div>
        <UploadZone
          file={phase === 'idle' || phase === 'uploading' ? file : null}
          onFile={setFile}
          onClear={() => setFile(null)}
          uploadProgress={isUploading ? uploadProgress : null}
        />

        {uploadResult && (
          <div className="file-pill fade-in" style={{ marginTop: '0.875rem' }}>
            <span className="file-pill-icon">📊</span>
            <span className="file-pill-name">{uploadResult.original_filename}</span>
            <span className="file-pill-size">{formatBytes(uploadResult.file_size_bytes)}</span>
            <span style={{ fontFamily: 'var(--mono)', fontSize: '0.72rem', color: 'var(--cyan)' }}>#{uploadResult.dataset_id}</span>
          </div>
        )}

        {isError && <div className="error-banner fade-in" style={{ marginTop: '0.875rem' }}>⚠️ {error}</div>}

        <div className="btn-row">
          {phase === 'idle' && <button className="btn btn-primary" disabled={!file} onClick={handleUpload} id="upload-btn">Upload Dataset</button>}
          {isUploading && <button className="btn btn-primary" disabled><span className="spinner" /> Uploading…</button>}
          {phase === 'uploaded' && (
            <>
              <button className="btn btn-primary" onClick={handleScan} id="scan-btn">🔍 Run Scan</button>
              <button className="btn btn-ghost" onClick={reset}>Cancel</button>
            </>
          )}
          {isScanning && <button className="btn btn-primary" disabled><span className="spinner" /> Scanning…</button>}
          {(isDone || isError) && <button className="btn btn-ghost" onClick={reset}>↺ New Scan</button>}
        </div>
      </div>

      {/* Pipeline Steps */}
      {phase !== 'idle' && (
        <div className="card fade-in">
          <div className="card-title">Pipeline</div>
          <div className="steps">
            <StepRow done={!['idle', 'uploading'].includes(phase)} active={isUploading} label="File upload & SHA-256 verification" />
            <StepRow done={['scanning', 'done'].includes(phase)} active={false} label="Dataset saved to secure store" />
            <StepRow done={isDone} active={isScanning} label="ClamAV virus scan + deobfuscation + content rule inspection" />
            <StepRow done={isDone} active={false} label="Risk scoring & verdict assignment" />
          </div>
        </div>
      )}

      {/* Scan Results */}
      {isDone && scanResult && (
        <div className="card fade-in">
          <div className="card-title">Scan Results</div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem', marginBottom: '1.5rem', flexWrap: 'wrap' }}>
            <RiskMeter score={scanResult.risk_score} verdict={scanResult.verdict} />
            <div>
              <StatusBadge verdict={scanResult.verdict} />
              <div style={{ marginTop: '0.75rem', display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-3)' }}>
                  ClamAV: <span style={{ color: 'var(--text-2)', fontFamily: 'var(--mono)' }}>{scanResult.clamav_status}</span>
                  {scanResult.clamav_virus_name && <span style={{ color: 'var(--rose)', marginLeft: '0.5rem' }}>— {scanResult.clamav_virus_name}</span>}
                </div>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-3)' }}>
                  Duration: <span style={{ color: 'var(--text-2)', fontFamily: 'var(--mono)' }}>{scanResult.scan_duration_ms} ms</span>
                </div>
              </div>
            </div>
          </div>

          <div className="report-summary">
            <div className="stat">
              <div className="stat-label">Threats Found</div>
              <div className="stat-value" style={{ color: scanResult.threats_found_count > 0 ? 'var(--rose)' : 'var(--emerald)' }}>
                {scanResult.threats_found_count}
              </div>
            </div>
            <div className="stat">
              <div className="stat-label">Risk Score</div>
              <div className="stat-value">{scanResult.risk_score.toFixed(1)}</div>
            </div>
            <div className="stat">
              <div className="stat-label">ClamAV</div>
              <div className="stat-value" style={{ fontSize: '1rem' }}>
                {scanResult.clamav_status === 'skipped' ? '⚠ offline'
                  : scanResult.clamav_status === 'clean' ? '✔ clean'
                  : '✕ infected'}
              </div>
            </div>
            <div className="stat">
              <div className="stat-label">Dataset ID</div>
              <div className="stat-value" style={{ fontSize: '1rem', fontFamily: 'var(--mono)' }}>#{scanResult.dataset_id}</div>
            </div>
          </div>

          {scanResult.clamav_status === 'skipped' && (
            <div style={{
              padding: '0.625rem 1rem', marginBottom: '1rem',
              background: 'rgba(245,158,11,0.06)', border: '1px solid rgba(245,158,11,0.2)',
              borderRadius: 'var(--r-sm)', fontSize: '0.8rem', color: 'var(--amber)',
              display: 'flex', gap: '0.5rem', alignItems: 'center',
            }}>
              ⚠️ ClamAV daemon is offline. Virus scanning was skipped — rule-based detection still active.
            </div>
          )}

          <FindingsList findings={scanResult.findings} />
          <RemediationCard datasetId={scanResult.dataset_id} scanResult={scanResult} />
          <AiSummary datasetId={scanResult.dataset_id} />
        </div>
      )}

      {uploadResult && (
        <div style={{ fontSize: '0.75rem', color: 'var(--text-3)', fontFamily: 'var(--mono)', textAlign: 'center', opacity: 0.6 }}>
          SHA-256: {uploadResult.sha256_hash}
        </div>
      )}
    </>
  );
}

// ─── Root App ──────────────────────────────────────────────
export default function App() {
  const [health, setHealth] = useState(null);
  const [tab, setTab] = useState('scan');

  useEffect(() => {
    healthCheck()
      .then(data => setHealth(data))
      .catch(() => setHealth({ status: 'error' }));
  }, []);

  return (
    <>
      <header className="header">
        <div className="brand">
          <div className="brand-shield">🛡️</div>
          <div>
            <div className="brand-name">Aegis Node</div>
            <div className="brand-sub">Dataset Threat Detection & Remediation</div>
          </div>
        </div>
        <HealthStatus health={health} />
      </header>

      <main className="main">
        <TabBar active={tab} onChange={setTab} />
        {tab === 'scan'    && <ScanPage />}
        {tab === 'history' && <HistoryPage />}
      </main>

      <footer className="footer">
        Aegis Node &copy; 2026 &bull; Secure Dataset Analysis Framework &bull; M.Tech Project
      </footer>
    </>
  );
}
