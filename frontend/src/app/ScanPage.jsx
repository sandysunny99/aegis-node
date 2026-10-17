import { useCallback, useState } from 'react';
import { scanDataset, uploadDataset } from '../api';
import AiSummary from '../components/AiSummary';
import FindingsList from '../components/FindingsList';
import RemediationCard from '../components/RemediationCard';
import ThreatIntelligence from '../components/ThreatIntelligence';
import TurnstileWidget from '../components/TurnstileWidget';
import UploadZone from '../components/UploadZone';
import { formatBytes } from '../data/useDatasets';
import { describeLimitation, detectorGaps } from '../status/limitations';
import { VERDICT_TO_STATUS } from '../status/statusToPlate';
import Button from '../ui/Button';
import Card from '../ui/Card';
import Icon from '../ui/Icon';
import StatusPill from '../ui/StatusPill';

const STEPS = ['Upload dataset', 'Scan', 'Review findings', 'Remediate'];

function Stepper({ currentStep }) {
  return (
    <ol className="stepper" aria-label="Scan progress">
      {STEPS.map((label, i) => {
        const num = i + 1;
        const done = currentStep > num;
        return (
          <li key={label} className={done ? 'is-done' : undefined} aria-current={currentStep === num ? 'step' : undefined}>
            <span className="stepper__num" aria-hidden="true">{num}</span>
            {label}
            {done && <span className="visually-hidden"> (done)</span>}
          </li>
        );
      })}
    </ol>
  );
}

function ScanSummary({ result }) {
  return (
    <dl className="summary">
      <div><dt>Verdict</dt><dd><StatusPill status={VERDICT_TO_STATUS[result.verdict] ?? 'incomplete'} /></dd></div>
      <div><dt>Risk score</dt><dd>{result.risk_score.toFixed(1)} / 10</dd></div>
      <div><dt>Findings</dt><dd>{result.threats_found_count}</dd></div>
      <div><dt>Coverage</dt><dd>{result.coverage_percentage}% ({result.coverage_status})</dd></div>
      <div><dt>Scan time</dt><dd>{result.scan_duration_ms} ms</dd></div>
    </dl>
  );
}

function Limitations({ codes }) {
  if (!codes?.length) return null;
  return (
    <div className="notice notice--risk" role="note">
      <Icon name="ShieldMinus" className="notice__icon" />
      <div>
        <strong>This result has limitations</strong>
        <ul className="notice__list">
          {codes.map((c) => <li key={c}>{describeLimitation(c)} <span className="mono muted">({c})</span></li>)}
        </ul>
      </div>
    </div>
  );
}

function LocalDetection({ result }) {
  const gaps = detectorGaps(result.verification_limitations);
  return (
    <Card title="Local detection" id="local-detection">
      <p className="card-sub card-lede">The deterministic scanner decides the verdict. AI and threat intelligence only add context.</p>
      <dl className="kv kv--spaced">
        <dt>Antivirus</dt>
        <dd>{result.clamav_status}{result.clamav_virus_name ? ` (${result.clamav_virus_name})` : ''}</dd>
        <dt>Detectors not run</dt>
        <dd>{gaps.length ? gaps.map((g) => `${g.name}: ${g.state}`).join('; ') : 'none reported'}</dd>
      </dl>
      <FindingsList findings={result.findings} />
    </Card>
  );
}

/** Upload, scan, review and remediate one dataset (the original scanner flow). */
export default function ScanPage({ health, onScanned }) {
  const [file, setFile] = useState(null);
  const [phase, setPhase] = useState('idle');
  const [uploadProgress, setUploadProgress] = useState(null);
  const [uploadResult, setUploadResult] = useState(null);
  const [scanResult, setScanResult] = useState(null);
  const [error, setError] = useState('');
  const [turnstileToken, setTurnstileToken] = useState(null);

  const reset = useCallback(() => {
    setFile(null); setPhase('idle'); setUploadProgress(null);
    setUploadResult(null); setScanResult(null); setError(''); setTurnstileToken(null);
  }, []);

  const handleUpload = useCallback(async () => {
    if (!file) return;
    setPhase('uploading'); setError(''); setUploadProgress(0);
    try {
      const r = await uploadDataset(file, (pct) => setUploadProgress(pct), turnstileToken);
      setUploadResult(r); setPhase('uploaded'); setUploadProgress(null);
      onScanned?.();
    } catch (e) { setError(e.message); setPhase('error'); setUploadProgress(null); }
  }, [file, turnstileToken, onScanned]);

  const handleScan = useCallback(async () => {
    if (!uploadResult) return;
    setPhase('scanning'); setError('');
    try {
      const r = await scanDataset(uploadResult.dataset_id);
      setScanResult(r); setPhase('done');
      onScanned?.();
    } catch (e) { setError(e.message); setPhase('scan-error'); }
  }, [uploadResult, onScanned]);

  const isUploading = phase === 'uploading';
  const isScanning = phase === 'scanning';
  const isDone = phase === 'done';
  const hasError = phase === 'error' || phase === 'scan-error';
  const selectingFile = phase === 'idle' || isUploading || phase === 'error';

  const currentStep = selectingFile ? 1
    : phase === 'uploaded' || isScanning || phase === 'scan-error' ? 2
    : scanResult?.threats_found_count > 0 ? 3 : 4;

  return (
    <div className="panel">
      {health?.av_mock_mode && (
        <div className="notice notice--risk" role="note">
          <Icon name="CircleAlert" className="notice__icon" />
          <span>The antivirus engine is simulated (mock mode). Heuristic, YARA and content checks still run; antivirus results are not real.</span>
        </div>
      )}

      <Stepper currentStep={currentStep} />

      <Card title="Dataset file" id="dataset-file">
        <UploadZone
          file={selectingFile ? file : null}
          onFile={(newFile) => {
            setFile(newFile);
            if (!selectingFile) {
              setPhase('idle'); setUploadResult(null); setScanResult(null); setError(''); setTurnstileToken(null);
            }
          }}
          onClear={() => { setFile(null); if (!selectingFile) reset(); }}
          uploadProgress={isUploading ? uploadProgress : null}
        />

        {uploadResult && (
          <div className="file-pill">
            <span className="file-pill-name">{uploadResult.original_filename}</span>
            <span className="file-pill-size">{formatBytes(uploadResult.file_size_bytes)}</span>
            <span className="file-pill-id" title="Dataset ID">{uploadResult.dataset_id.slice(0, 12)}</span>
          </div>
        )}

        {hasError && (
          <div className="error-banner error-banner--spaced" role="alert">
            <Icon name="CircleAlert" />
            <span>{error}</span>
          </div>
        )}

        {phase === 'idle' && health?.turnstile_enabled && (
          <TurnstileWidget siteKey={health?.turnstile_site_key} onVerify={setTurnstileToken} onExpire={() => setTurnstileToken(null)} />
        )}

        <div className="btn-row">
          {selectingFile && (
            <Button
              variant="primary"
              loading={isUploading}
              disabled={!file || (health?.turnstile_enabled && !turnstileToken)}
              onClick={handleUpload}
              id="upload-btn"
            >
              Upload dataset
            </Button>
          )}
          {(phase === 'uploaded' || isScanning || phase === 'scan-error') && (
            <>
              <Button variant="primary" loading={isScanning} onClick={handleScan} id="scan-btn">
                {phase === 'scan-error' ? 'Scan again' : 'Scan dataset'}
              </Button>
              {!isScanning && <Button variant="ghost" onClick={reset}>Cancel</Button>}
            </>
          )}
          {isDone && (
            <>
              <Button variant="secondary" onClick={() => { window.location.hash = `/app/datasets/${uploadResult.dataset_id}`; }}>
                Open dataset page
              </Button>
              <Button variant="ghost" onClick={reset}>Scan another dataset</Button>
            </>
          )}
        </div>
      </Card>

      {isDone && scanResult && (
        <section aria-label="Scan report" className="report">
          <h2>Scan report: {uploadResult?.original_filename}</h2>
          <ScanSummary result={scanResult} />
          <Limitations codes={scanResult.verification_limitations} />
          <LocalDetection result={scanResult} />
          <ThreatIntelligence tiReport={scanResult.threat_intel} />
          <AiSummary datasetId={scanResult.dataset_id} />
          <RemediationCard datasetId={scanResult.dataset_id} scanResult={scanResult} />
        </section>
      )}

      {uploadResult && <p className="muted mono hash-line">SHA-256 {uploadResult.sha256_hash}</p>}
    </div>
  );
}
