import { useCallback, useEffect, useState } from 'react';
import { getScan, getScanEvents } from '../api';
import EventTimeline from '../components/EventTimeline';
import FindingsList from '../components/FindingsList';
import ThreatIntelligence from '../components/ThreatIntelligence';
import { formatBytes, formatTime } from '../data/useDatasets';
import { enrichmentLabel, historyMissing, notRecorded, verdictStatus } from '../status/history';
import { describeLimitation } from '../status/limitations';
import Button from '../ui/Button';
import Card from '../ui/Card';
import Icon from '../ui/Icon';
import Skeleton from '../ui/Skeleton';
import StatusPill from '../ui/StatusPill';
import { HistoryMissingNotice, PersistenceNotice } from './HistoryPage';

const isNotFound = (err) => err?.status === 404;

/** One scan (GET /scans/{id}) and its event timeline (GET /scans/{id}/events). */
export default function ScanDetailPage({ id, datasets }) {
  const [scan, setScan] = useState(null);
  const [state, setState] = useState('loading'); // loading | ready | missing | absent | error
  const [error, setError] = useState('');
  const [events, setEvents] = useState(null);
  const [eventsError, setEventsError] = useState('');

  const loadEvents = useCallback(() => {
    setEvents(null); setEventsError('');
    getScanEvents(id).then(setEvents).catch((err) => setEventsError(err.message));
  }, [id]);

  const load = useCallback(() => {
    setState('loading');
    getScan(id)
      .then((s) => { setScan(s); setState('ready'); loadEvents(); })
      .catch((err) => {
        if (historyMissing(err)) setState('absent');
        else if (isNotFound(err)) setState('missing');
        else { setError(err.message); setState('error'); }
      });
  }, [id, loadEvents]);

  useEffect(() => { load(); }, [load]);

  if (state === 'loading') {
    return (
      <div className="detail" aria-label="Loading scan">
        <Skeleton height="72px" />
        <div className="detail__grid"><Skeleton height="320px" /><Skeleton height="320px" /></div>
      </div>
    );
  }
  if (state === 'absent') return <Card title="Scan" id="scan-absent"><HistoryMissingNotice /></Card>;
  if (state === 'missing') {
    return (
      <Card title="Scan not found" id="scan-missing">
        <p className="muted">No scan has this ID. The server data may have been reset.</p>
        <div className="btn-row"><Button variant="secondary" onClick={() => { window.location.hash = '/app/history'; }}>Back to history</Button></div>
      </Card>
    );
  }
  if (state === 'error') {
    return (
      <div className="error-banner" role="alert">
        <Icon name="CircleAlert" />
        <span>This scan could not be loaded: {error}</span>
        <Button variant="ghost" onClick={load}>Retry</Button>
      </div>
    );
  }

  const name = datasets.find((d) => d.dataset_id === scan.dataset_id)?.original_filename;
  const rows = scan.rows_total != null ? `${scan.rows_inspected} of ${scan.rows_total} rows` : `${scan.rows_inspected} rows`;

  return (
    <div className="detail">
      <header className="detail__head">
        <div>
          <h1 className="detail__title break">
            {scan.target === 'sanitized' ? 'Verification re-scan' : 'Scan'} of {name ?? 'dataset'}
          </h1>
          <div className="detail__meta">
            <StatusPill status={verdictStatus(scan.verdict)} />
            <span className="muted mono">{scan.scan_id}</span>
          </div>
        </div>
        <div className="detail__actions">
          <Button variant="secondary" onClick={() => { window.location.hash = `/app/datasets/${scan.dataset_id}`; }}>Open dataset</Button>
        </div>
      </header>

      {events && <PersistenceNotice persistence={events.persistence} />}
      {scan.limitations?.length > 0 && (
        <div className="notice notice--risk" role="note">
          <Icon name="ShieldMinus" className="notice__icon" />
          <div>
            <strong>This result has limitations</strong>
            <ul className="notice__list">
              {scan.limitations.map((c) => <li key={c}>{describeLimitation(c)}</li>)}
            </ul>
          </div>
        </div>
      )}

      <div className="detail__grid">
        <div className="detail__main">
          <Card title="What happened" id="scan-events">
            {!events && !eventsError && <div className="stack-sm" aria-label="Loading events">{[0, 1, 2].map((i) => <Skeleton key={i} height="32px" />)}</div>}
            {eventsError && (
              <div className="error-banner" role="alert">
                <Icon name="CircleAlert" />
                <span>The event timeline could not be loaded: {eventsError}</span>
                <Button variant="ghost" onClick={loadEvents}>Retry</Button>
              </div>
            )}
            {events && <EventTimeline events={events.items} />}
            {events && <p className="muted table-note">Only steps that ran are listed. Scans recorded before history existed have no events.</p>}
          </Card>
          <ThreatIntelligence tiReport={scan.threat_intel} />
          <Card title="Findings" id="scan-findings"><FindingsList findings={scan.findings} /></Card>
        </div>
        <aside className="detail__side">
          <Card title="Scan details" id="scan-meta">
            <dl className="kv">
              <dt>Started</dt><dd>{scan.started_at ? formatTime(scan.started_at) : 'Not recorded'}</dd>
              <dt>Completed</dt><dd>{formatTime(scan.completed_at)}</dd>
              <dt>Scanned</dt><dd>{scan.target === 'sanitized' ? 'Sanitized copy' : 'Uploaded file'}</dd>
              <dt>Dataset now</dt><dd><StatusPill status={scan.dataset_status} size="sm" /></dd>
              <dt>Coverage</dt><dd>{scan.coverage_status === 'FULL' ? 'Full' : scan.coverage_status.toLowerCase()} ({rows})</dd>
              <dt>Antivirus</dt><dd>{scan.clamav_status} (engine: {notRecorded(scan.av_provider)})</dd>
              <dt>Profile</dt><dd>{notRecorded(scan.profile)}</dd>
              <dt>Threat intel</dt><dd>{enrichmentLabel(scan.enrichment_status)}</dd>
              <dt>Risk score</dt><dd>{scan.risk_score.toFixed(1)} / 10</dd>
              <dt>Findings</dt><dd>{scan.threats_found_count}</dd>
              <dt>Format</dt><dd>{scan.file_format.toUpperCase()}, {formatBytes(scan.file_size_bytes)}</dd>
              <dt>SHA-256</dt><dd className="break">{scan.sha256}</dd>
            </dl>
          </Card>
        </aside>
      </div>
    </div>
  );
}
