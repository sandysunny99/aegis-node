import React, { useCallback, useEffect, useState } from 'react';
import { healthCheck, scanDataset, uploadDataset } from './api';
import AiSummary from './components/AiSummary';
import FindingsList from './components/FindingsList';
import RemediationCard from './components/RemediationCard';
import RiskMeter from './components/RiskMeter';
import StatusBadge from './components/StatusBadge';
import ThreatIntelligence from './components/ThreatIntelligence';
import TurnstileWidget from './components/TurnstileWidget';
import UploadZone from './components/UploadZone';
import HistoryPage from './pages/HistoryPage';

// ─── Utility ───────────────────────────────────────────────
function formatBytes(b) {
  if (!b) return '0 B';
  if (b < 1024) return `${b} B`;
  if (b < 1024 ** 2) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1024 ** 2).toFixed(1)} MB`;
}

// ─── Pipeline Stepper ──────────────────────────────────────
function Stepper({ currentStep }) {
  const steps = [
    { num: 1, label: 'Upload Dataset' },
    { num: 2, label: 'Security Scan' },
    { num: 3, label: 'AI & Threat Insights' },
    { num: 4, label: 'Remediation' },
  ];

  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      background: 'var(--bg-2)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--r-lg)',
      padding: '0.875rem 1.25rem',
      marginBottom: '1rem',
      gap: '0.5rem',
      flexWrap: 'wrap',
    }}>
      {steps.map((s, idx) => {
        const isDone = currentStep > s.num;
        const isCurrent = currentStep === s.num;
        const color = isDone ? 'var(--emerald)' : isCurrent ? 'var(--cyan)' : 'var(--text-3)';
        const bg = isDone ? 'rgba(16,185,129,0.15)' : isCurrent ? 'rgba(6,182,212,0.15)' : 'rgba(255,255,255,0.03)';
        const border = isDone ? 'rgba(16,185,129,0.4)' : isCurrent ? 'rgba(6,182,212,0.4)' : 'var(--border)';

        return (
          <React.Fragment key={s.num}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <div style={{
                width: '26px', height: '26px', borderRadius: '50%',
                background: bg, border: `1px solid ${border}`,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                color, fontWeight: 700, fontSize: '0.75rem', fontFamily: 'var(--mono)',
              }}>
                {isDone ? '✓' : s.num}
              </div>
              <span style={{
                fontSize: '0.8rem',
                fontWeight: isCurrent ? 700 : 500,
                color: isCurrent ? 'var(--text-1)' : isDone ? 'var(--text-2)' : 'var(--text-3)',
              }}>
                {s.label}
              </span>
            </div>
            {idx < steps.length - 1 && (
              <div style={{
                flex: 1, height: '2px', minWidth: '16px',
                background: isDone ? 'var(--emerald)' : 'var(--border)',
                transition: 'background 0.3s',
              }} />
            )}
          </React.Fragment>
        );
      })}
    </div>
  );
}

// ─── Tab Bar ───────────────────────────────────────────────
function TabBar({ active, onChange }) {
  const tabs = [
    { id: 'scan',    label: '🛡️ Threat Scanner' },
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
            fontFamily: 'var(--font)', fontWeight: 600, fontSize: '0.85rem',
            padding: '0.5rem 1.25rem', cursor: 'pointer',
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
    <div style={{ display: 'flex', alignItems: 'center', gap: '0.875rem', flexWrap: 'wrap' }}>
      {/* API Status */}
      <div className="header-status">
        <span className={online ? 'pulse' : undefined}
          style={!online ? { width: 8, height: 8, borderRadius: '50%', background: 'var(--rose)', boxShadow: '0 0 8px var(--rose)', display: 'inline-block' } : {}} />
        {online ? 'API Online' : 'API Offline'}
      </div>

      {/* ClamAV */}
      <div className="header-status" title={health.clamav_running ? 'ClamAV daemon active' : (health.clamav_mock ? 'ClamAV: Simulated (heuristics active)' : 'ClamAV offline — rule-based scanning active')}>
        <span style={{
          width: 7, height: 7, borderRadius: '50%', display: 'inline-block',
          background: health.clamav_running
            ? 'var(--emerald)'
            : (health.clamav_mock ? 'var(--cyan)' : 'var(--amber)'),
          boxShadow: health.clamav_running
            ? '0 0 6px var(--emerald)'
            : (health.clamav_mock ? '0 0 6px var(--cyan)' : '0 0 6px var(--amber)'),
        }} />
        {health.clamav_running
          ? 'ClamAV: Live'
          : (health.clamav_mock ? 'AV: Simulated' : 'No AV')}
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
function ScanPage({ health }) {
  const [file, setFile] = useState(null);
  const [phase, setPhase] = useState('idle');
  const [uploadProgress, setUploadProgress] = useState(null);
  const [uploadResult, setUploadResult] = useState(null);
  const [scanResult, setScanResult] = useState(null);
  const [error, setError] = useState('');
  const [turnstileToken, setTurnstileToken] = useState(null);

  const reset = useCallback(() => {
    setFile(null); setPhase('idle');
    setUploadProgress(null);
    setUploadResult(null); setScanResult(null); setError('');
    setTurnstileToken(null);
  }, []);

  const handleUpload = useCallback(async () => {
    if (!file) return;
    setPhase('uploading'); setError(''); setUploadProgress(0);
    try {
      const r = await uploadDataset(file, (pct) => setUploadProgress(pct), turnstileToken);
      setUploadResult(r); setPhase('uploaded'); setUploadProgress(null);
    } catch (e) { setError(e.message); setPhase('error'); setUploadProgress(null); }
  }, [file, turnstileToken]);

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

  // Compute current step for stepper
  const currentStep = phase === 'idle' || phase === 'uploading' ? 1
    : phase === 'uploaded' || phase === 'scanning' ? 2
    : isDone ? (scanResult?.threats_found_count > 0 ? 3 : 4) : 1;

  return (
    <>
      {/* Simulation Banner if ClamAV mock mode is active (A-019) */}
      {health?.clamav_mock && (
        <div style={{
          padding: '0.625rem 1rem',
          background: 'rgba(6,182,212,0.08)',
          border: '1px solid rgba(6,182,212,0.25)',
          borderRadius: 'var(--r-sm)',
          fontSize: '0.8rem',
          color: 'var(--cyan)',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
        }}>
          <span>ℹ️</span>
          <span>
            <strong>Simulated ClamAV Mode Active:</strong> High-performance signature-less heuristic scanning and deterministic rule engines are running fully.
          </span>
        </div>
      )}

      {/* Stepper */}
      <Stepper currentStep={currentStep} />

      {/* Upload Card */}
      <div className="card">
        <div className="card-title">Dataset File Input</div>
        <UploadZone
          file={phase === 'idle' || phase === 'uploading' ? file : null}
          onFile={(newFile) => {
            setFile(newFile);
            if (phase === 'done' || phase === 'uploaded' || phase === 'error') {
              setPhase('idle');
              setUploadResult(null);
              setScanResult(null);
              setError('');
              setTurnstileToken(null);
            }
          }}
          onClear={() => {
            setFile(null);
            if (phase === 'done' || phase === 'uploaded' || phase === 'error') {
              reset();
            }
          }}
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

        {phase === 'idle' && health?.turnstile_enabled && (
          <TurnstileWidget
            siteKey={health?.turnstile_site_key}
            onVerify={setTurnstileToken}
            onExpire={() => setTurnstileToken(null)}
          />
        )}

        <div className="btn-row">
          {phase === 'idle' && (
            <button
              className="btn btn-primary"
              disabled={!file || (health?.turnstile_enabled && !turnstileToken)}
              onClick={handleUpload}
              id="upload-btn"
            >
              ⬆ Upload Dataset
            </button>
          )}
          {isUploading && (
            <button className="btn btn-primary" disabled>
              <span className="spinner" /> Uploading…
            </button>
          )}
          {phase === 'uploaded' && (
            <>
              <button className="btn btn-primary" onClick={handleScan} id="scan-btn">
                🔍 Start Multi-Stage Scan
              </button>
              <button className="btn btn-ghost" onClick={reset}>Cancel</button>
            </>
          )}
          {isScanning && (
            <button className="btn btn-primary" disabled>
              <span className="spinner" /> Analyzing Dataset…
            </button>
          )}
          {(isDone || isError) && (
            <button className="btn btn-ghost" onClick={reset}>
              ↺ Scan Another Dataset
            </button>
          )}
        </div>
      </div>

      
      {/* Scan Results */}
      {isDone && scanResult && (
        <div className="fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <div style={{ fontSize: '1.1rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span>📄</span> Multi-Stage Security Report: {scanResult.dataset_id}
          </div>

          {/* COMPACT RESULT HEADER */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '1rem', background: 'var(--bg-1)', padding: '1rem', borderRadius: 'var(--r-md)', border: '1px solid var(--border)', fontFamily: 'var(--mono)', fontSize: '0.8rem' }}>
             <div style={{ flex: 1, minWidth: '120px' }}><div style={{ color: 'var(--text-3)', fontSize: '0.65rem' }}>VERDICT</div><StatusBadge verdict={scanResult.verdict} /></div>
             <div style={{ flex: 1, minWidth: '120px' }}><div style={{ color: 'var(--text-3)', fontSize: '0.65rem' }}>RISK SCORE</div><strong style={{ color: scanResult.risk_score > 6 ? 'var(--rose)' : scanResult.risk_score > 3 ? 'var(--amber)' : 'var(--emerald)' }}>{scanResult.risk_score.toFixed(1)}/10</strong></div>
             <div style={{ flex: 1, minWidth: '120px' }}><div style={{ color: 'var(--text-3)', fontSize: '0.65rem' }}>DETECTIONS</div><strong style={{ color: scanResult.threats_found_count > 0 ? 'var(--rose)' : 'var(--emerald)' }}>{scanResult.threats_found_count}</strong></div>
             <div style={{ flex: 1, minWidth: '120px' }}><div style={{ color: 'var(--text-3)', fontSize: '0.65rem' }}>COVERAGE</div><strong style={{ color: 'var(--cyan)' }}>{scanResult.coverage_percentage ?? 100}%</strong></div>
             <div style={{ flex: 1, minWidth: '120px' }}><div style={{ color: 'var(--text-3)', fontSize: '0.65rem' }}>SCAN TIME</div><strong style={{ color: 'var(--text-1)' }}>{scanResult.scan_duration_ms} ms</strong></div>
          </div>

          {/* B. LOCAL DETECTION */}
          <div className="card">
            <div className="card-title">LOCAL DETECTION <span style={{fontSize: '0.7rem', color: 'var(--text-3)', fontWeight: 400}}>(Primary Authority)</span></div>
            <div style={{ display: 'flex', gap: '1.5rem', marginBottom: '1rem', fontSize: '0.85rem' }}>
              <div>ClamAV: <strong style={{ color: 'var(--text-1)' }}>{scanResult.clamav_status}</strong> {scanResult.clamav_virus_name && <span style={{color: 'var(--rose)'}}>({scanResult.clamav_virus_name})</span>}</div>
              <div>YARA: <strong style={{ color: 'var(--text-1)' }}>Enabled</strong></div>
              <div>Heuristics: <strong style={{ color: 'var(--text-1)' }}>Active</strong></div>
            </div>
            <FindingsList findings={scanResult.findings} />
          </div>

          {/* C. THREAT INTELLIGENCE */}
          <ThreatIntelligence tiReport={scanResult.threat_intel} />

          {/* D. AI SECURITY */}
          <AiSummary datasetId={scanResult.dataset_id} />

          {/* E & F. REMEDIATION & VERIFICATION */}
          <RemediationCard datasetId={scanResult.dataset_id} scanResult={scanResult} />
        </div>
      )}
{uploadResult && (
        <div style={{ fontSize: '0.72rem', color: 'var(--text-3)', fontFamily: 'var(--mono)', textAlign: 'center', opacity: 0.6 }}>
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
      <header className="header" style={{ display: 'flex', flexWrap: 'wrap', gap: '1rem', justifyContent: 'space-between', alignItems: 'center' }}>
        <div className="brand" style={{ flexShrink: 0 }}>
          <div className="brand-shield">🛡️</div>
          <div>
            <div className="brand-name">Aegis Node</div>
            <div className="brand-sub">Dataset Threat Detection & Remediation</div>
          </div>
        </div>
        <div style={{ flex: '1 1 auto', overflowX: 'auto' }}>
          <HealthStatus health={health} />
        </div>
      </header>

      <main className="main">
        <TabBar active={tab} onChange={setTab} />
        {tab === 'scan'    && <ScanPage health={health} />}
        {tab === 'history' && <HistoryPage />}
      </main>

      <footer className="footer">
        Aegis Node &copy; 2026 &bull; Threat Detection & Risk-Based Remediation &bull; M.Tech Project
      </footer>
    </>
  );
}

