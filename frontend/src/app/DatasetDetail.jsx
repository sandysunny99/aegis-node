import { useCallback, useEffect, useState } from 'react';
import { getDatasetStatus, getRemediationReport, getScanReport, scanDataset } from '../api';
import AiSummary from '../components/AiSummary';
import RemediationCard from '../components/RemediationCard';
import ResultLayers from '../components/ResultLayers';
import ThreatIntelligence from '../components/ThreatIntelligence';
import { formatBytes, formatTime } from '../data/useDatasets';
import { describeLimitation, detectorGaps } from '../status/limitations';
import { VERDICT_TO_STATUS, effectiveStatus, statusToPlate } from '../status/statusToPlate';
import { plainDashes } from '../status/text';
import Button from '../ui/Button';
import Card from '../ui/Card';
import Icon from '../ui/Icon';
import Skeleton from '../ui/Skeleton';
import StatusPill from '../ui/StatusPill';

const isNotFound = (err) => /not found|404/i.test(err?.message ?? '');
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const REMEDIATED = new Set(['remediated', 'partial_remediated', 'remediated_unverified']);

function FindingsBySeverity({ findings }) {
  if (!findings?.length) return <p className="empty">The latest scan reported no findings.</p>;
  const groups = SEVERITIES
    .map((sev) => [sev, findings.filter((f) => (f.severity || '').toLowerCase().startsWith(sev))])
    .filter(([, list]) => list.length);
  return (
    <div className="sev-groups">
      {groups.map(([sev, list]) => (
        <section key={sev} aria-labelledby={`sev-${sev}`}>
          <h3 id={`sev-${sev}`} className={`sev-groups__title finding__sev--${sev}`}>{sev} ({list.length})</h3>
          <ul className="findings">
            {list.map((f, i) => (
              <li key={`${f.rule_id}-${f.location}-${i}`} className="finding">
                <div className="finding__top">
                  <span className="finding__rule">{f.rule_id}</span>
                  <span className="finding__loc">{f.category}</span>
                </div>
                <p>{plainDashes(f.description)}</p>
                {f.location && <p className="finding__loc">Where: {f.location}</p>}
                {f.sample && <pre className="evidence"><code>{f.sample}</code></pre>}
              </li>
            ))}
          </ul>
        </section>
      ))}
    </div>
  );
}

function Timeline({ dataset, report, remediation }) {
  const events = [
    { at: dataset.uploaded_at, text: `Uploaded (${formatBytes(dataset.file_size_bytes)})` },
    report && { at: report.scanned_at, text: `Latest scan: ${statusToPlate(VERDICT_TO_STATUS[report.verdict] ?? 'incomplete').label}, ${report.threats_found_count} finding${report.threats_found_count === 1 ? '' : 's'}` },
    report?.verdict === 'malicious' && { at: report.scanned_at, text: 'Quarantined automatically after the malicious verdict' },
    remediation && { at: remediation.remediated_at, text: `Remediation ${remediation.remediation_status}` },
  ].filter(Boolean);
  return (
    <ol className="timeline">
      {events.map((e) => (
        <li key={e.text}>
          <span className="timeline__dot" aria-hidden="true" />
          <span>{e.text}</span>
          <time className="mono muted" dateTime={e.at}>{formatTime(e.at, '')}</time>
        </li>
      ))}
    </ol>
  );
}

export default function DatasetDetail({ id, onChanged }) {
  const [dataset, setDataset] = useState(null);
  const [report, setReport] = useState(null);
  const [remediation, setRemediation] = useState(null);
  const [analysis, setAnalysis] = useState(undefined); // undefined = loading, null = none
  const [state, setState] = useState('loading'); // loading | ready | missing | error
  const [error, setError] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState('');

  const load = useCallback(async () => {
    setState('loading');
    try {
      const d = await getDatasetStatus(id);
      setDataset(d);
      setReport(await getScanReport(id).catch((err) => (isNotFound(err) ? null : Promise.reject(err))));
      setRemediation(await getRemediationReport(id).catch((err) => (isNotFound(err) ? null : Promise.reject(err))));
      setState('ready');
    } catch (err) {
      if (isNotFound(err)) setState('missing');
      else { setError(err.message); setState('error'); }
    }
  }, [id]);

  useEffect(() => { load(); }, [load]);

  const rescan = async () => {
    setScanning(true); setScanError('');
    try {
      await scanDataset(id);
      await load();
      onChanged?.();
    } catch (err) {
      setScanError(err.message);
    }
    setScanning(false);
  };

  if (state === 'loading') {
    return (
      <div className="detail" aria-label="Loading dataset">
        <Skeleton height="72px" />
        <div className="detail__grid"><Skeleton height="320px" /><Skeleton height="320px" /></div>
      </div>
    );
  }
  if (state === 'missing') {
    return (
      <Card title="Dataset not found" id="detail-missing">
        <p className="muted">No dataset has this ID. It may belong to another browser or the server data may have been reset.</p>
        <div className="btn-row"><Button variant="secondary" onClick={() => { window.location.hash = '/app/datasets'; }}>Back to datasets</Button></div>
      </Card>
    );
  }
  if (state === 'error') {
    return (
      <div className="error-banner" role="alert">
        <Icon name="CircleAlert" />
        <span>This dataset could not be loaded: {error}</span>
        <Button variant="ghost" onClick={load}>Retry</Button>
      </div>
    );
  }

  const shown = effectiveStatus(dataset.status, report?.verdict);
  const canRescan = !REMEDIATED.has(dataset.status) && dataset.status !== 'scanning';
  const gaps = detectorGaps(report?.verification_limitations);

  return (
    <div className="detail">
      <header className="detail__head">
        <div>
          <h1 className="detail__title break">{dataset.original_filename}</h1>
          <div className="detail__meta">
            <StatusPill status={shown} />
            <span className="muted mono">{dataset.dataset_id}</span>
          </div>
        </div>
        <div className="detail__actions">
          {canRescan && (
            <Button variant={report ? 'secondary' : 'primary'} onClick={rescan} loading={scanning}>
              {report ? 'Scan again' : 'Scan dataset'}
            </Button>
          )}
          {!canRescan && REMEDIATED.has(dataset.status) && (
            <p className="muted detail__hint">The original is not rescanned after remediation; the sanitized copy was re-scanned instead.</p>
          )}
        </div>
      </header>

      {scanError && (
        <div className="error-banner" role="alert"><Icon name="CircleAlert" /><span>{scanError}</span></div>
      )}
      {shown === 'quarantined' && (
        <div className="notice notice--error" role="note">
          <Icon name="ShieldX" className="notice__icon" />
          <span>
            Quarantined automatically after a malicious verdict
            {report?.scanned_at ? ` on ${formatTime(report.scanned_at)}` : ''}. The file is kept apart from other uploads; remediation can still produce a sanitized copy.
          </span>
        </div>
      )}
      {report?.verification_limitations?.length > 0 && (
        <div className="notice notice--risk" role="note">
          <Icon name="ShieldMinus" className="notice__icon" />
          <div>
            <strong>This result has limitations</strong>
            <ul className="notice__list">
              {report.verification_limitations.map((c) => <li key={c}>{describeLimitation(c)}</li>)}
            </ul>
          </div>
        </div>
      )}

      <div className="detail__grid">
        <div className="detail__main">
          {report && <ResultLayers report={report} analysis={analysis} />}
          <Card title="Findings" id="detail-findings">
            {report ? <FindingsBySeverity findings={report.findings} /> : <p className="empty">This dataset has not been scanned yet.</p>}
          </Card>
          {report && <ThreatIntelligence tiReport={report.threat_intel} />}
          {report && <AiSummary datasetId={id} onAnalysis={setAnalysis} />}
          {report && <RemediationCard datasetId={id} scanResult={report} />}
        </div>
        <aside className="detail__side">
          <Card title="Scan history" id="detail-history">
            <Timeline dataset={dataset} report={report} remediation={remediation} />
            <p className="muted table-note">The API keeps the latest scan report per dataset.</p>
          </Card>
          <Card title="Metadata" id="detail-meta">
            <dl className="kv">
              <dt>Size</dt><dd>{formatBytes(dataset.file_size_bytes)}</dd>
              <dt>SHA-256</dt><dd className="break">{dataset.sha256_hash}</dd>
              <dt>Uploaded</dt><dd>{formatTime(dataset.uploaded_at)}</dd>
              {report && (<><dt>Rows inspected</dt><dd>{report.rows_inspected}{report.rows_total != null ? ` of ${report.rows_total}` : ''}</dd></>)}
              {report && (<><dt>Coverage</dt><dd>{report.coverage_percentage}% ({report.coverage_status})</dd></>)}
              {report && (<><dt>Risk score</dt><dd>{report.risk_score.toFixed(1)} / 10</dd></>)}
              {report && (<><dt>Antivirus</dt><dd>{report.clamav_status}{report.clamav_virus_name ? ` (${report.clamav_virus_name})` : ''}</dd></>)}
              {report && (<><dt>Detectors not run</dt><dd>{gaps.length ? gaps.map((g) => `${g.name}: ${g.state}`).join('; ') : 'none reported'}</dd></>)}
              {report && (<><dt>Scan time</dt><dd>{report.scan_duration_ms} ms</dd></>)}
            </dl>
          </Card>
        </aside>
      </div>
    </div>
  );
}
