import { useCallback, useEffect, useState } from 'react';
import { listScans } from '../api';
import { formatTime } from '../data/useDatasets';
import {
  DATASET_STATUS_FILTERS, ENRICHMENT_STATUSES, FILE_FORMATS, TARGETS, VERDICTS,
  enrichmentLabel, historyMissing, persistenceNote, verdictLabel, verdictStatus,
} from '../status/history';
import { statusToPlate } from '../status/statusToPlate';
import Button from '../ui/Button';
import Card from '../ui/Card';
import Icon from '../ui/Icon';
import Skeleton from '../ui/Skeleton';
import StatusPill from '../ui/StatusPill';
import ToneChip from '../ui/ToneChip';

const PAGE_SIZE = 20;
const NO_FILTERS = { verdict: 'all', dataset_status: 'all', file_format: 'all', enrichment_status: 'all', target: 'original', from: '', to: '' };
const ENRICHMENT_TONE = { COMPLETE: 'neutral', DISABLED: 'neutral', PARTIAL: 'risk', UNAVAILABLE: 'risk' };

function Select({ label, value, onChange, children }) {
  return (
    <label className="filters__status">
      <span>{label}</span>
      <select className="select" value={value} onChange={(e) => onChange(e.target.value)}>{children}</select>
    </label>
  );
}

export function PersistenceNotice({ persistence }) {
  const note = persistenceNote(persistence);
  if (!note) return null;
  return (
    <div className="notice notice--risk" role="note">
      <Icon name="CircleAlert" className="notice__icon" />
      <span>{note}</span>
    </div>
  );
}

export function HistoryMissingNotice() {
  return (
    <div className="notice notice--risk" role="note">
      <Icon name="CircleDashed" className="notice__icon" />
      <span>This server does not provide scan history yet, so only each dataset's latest scan can be shown. History appears here once the backend with the scan history API is deployed.</span>
    </div>
  );
}

/** GET /api/v1/scans for this browser's uploads: filters, stable paging, and every failure shown as a failure. */
export default function HistoryPage({ datasets }) {
  const [filters, setFilters] = useState(NO_FILTERS);
  const [page, setPage] = useState(1);
  const [data, setData] = useState(null);
  const [state, setState] = useState('loading'); // loading | ready | missing | error
  const [error, setError] = useState('');

  const load = useCallback(() => {
    setState('loading');
    listScans(filters, page, PAGE_SIZE)
      .then((d) => { setData(d); setState('ready'); })
      .catch((err) => {
        if (historyMissing(err)) setState('missing');
        else { setError(err.message); setState('error'); }
      });
  }, [filters, page]);

  useEffect(() => { load(); }, [load]);

  const set = (key) => (value) => { setFilters((f) => ({ ...f, [key]: value })); setPage(1); };
  const filtered = Object.keys(NO_FILTERS).some((k) => filters[k] !== NO_FILTERS[k]);
  const names = Object.fromEntries(datasets.map((d) => [d.dataset_id, d.original_filename]));
  const pages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;

  return (
    <Card title="Scan history" id="history">
      {state === 'ready' && <PersistenceNotice persistence={data.persistence} />}

      {state !== 'missing' && (
        <div className="filters" role="search" aria-label="Filter scans">
          <Select label="Verdict" value={filters.verdict} onChange={set('verdict')}>
            <option value="all">All verdicts</option>
            {VERDICTS.map((v) => <option key={v} value={v}>{verdictLabel(v)}</option>)}
          </Select>
          <Select label="Dataset now" value={filters.dataset_status} onChange={set('dataset_status')}>
            <option value="all">Any status</option>
            {DATASET_STATUS_FILTERS.map((s) => <option key={s} value={s}>{statusToPlate(s).label}</option>)}
          </Select>
          <Select label="Format" value={filters.file_format} onChange={set('file_format')}>
            <option value="all">All formats</option>
            {FILE_FORMATS.map((f) => <option key={f} value={f}>{f.toUpperCase()}</option>)}
          </Select>
          <Select label="Threat intel" value={filters.enrichment_status} onChange={set('enrichment_status')}>
            <option value="all">Any</option>
            {ENRICHMENT_STATUSES.map((s) => <option key={s} value={s}>{enrichmentLabel(s)}</option>)}
          </Select>
          <Select label="Scans of" value={filters.target} onChange={set('target')}>
            {TARGETS.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
          </Select>
          <label className="filters__status">
            <span>From</span>
            <input type="date" className="select" value={filters.from} max={filters.to || undefined} onChange={(e) => set('from')(e.target.value)} />
          </label>
          <label className="filters__status">
            <span>To</span>
            <input type="date" className="select" value={filters.to} min={filters.from || undefined} onChange={(e) => set('to')(e.target.value)} />
          </label>
          {filtered && <Button variant="ghost" onClick={() => { setFilters(NO_FILTERS); setPage(1); }}>Clear filters</Button>}
        </div>
      )}

      {state === 'loading' && (
        <div className="stack-sm" aria-label="Loading scan history">
          {[0, 1, 2, 3].map((i) => <Skeleton key={i} height="48px" />)}
        </div>
      )}
      {state === 'missing' && <HistoryMissingNotice />}
      {state === 'error' && (
        <div className="error-banner" role="alert">
          <Icon name="CircleAlert" />
          <span>Scan history could not be loaded: {error}</span>
          <Button variant="ghost" onClick={load}>Retry</Button>
        </div>
      )}
      {state === 'ready' && data.total === 0 && (
        <p className="empty">
          {filtered ? 'No scan matches these filters.' : datasets.length ? 'No scans recorded yet for datasets uploaded from this browser.' : 'No datasets have been uploaded from this browser yet.'}
        </p>
      )}
      {state === 'ready' && data.items.length > 0 && (
        <>
          <div className="table-wrap">
            <table className="table">
              <caption className="visually-hidden">Scans of datasets uploaded from this browser, newest first</caption>
              <thead>
                <tr>
                  <th scope="col">Completed</th>
                  <th scope="col">Dataset</th>
                  <th scope="col">Verdict</th>
                  <th scope="col">Dataset now</th>
                  <th scope="col">Threat intel</th>
                  <th scope="col">Coverage</th>
                  <th scope="col" className="is-numeric">Findings</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((s) => (
                  <tr key={s.scan_id}>
                    <td data-label="Completed"><a href={`#/app/history/${s.scan_id}`}>{formatTime(s.completed_at)}</a></td>
                    <td data-label="Dataset">
                      <a href={`#/app/datasets/${s.dataset_id}`} className="break">{names[s.dataset_id] ?? <span className="mono">{s.dataset_id.slice(0, 12)}</span>}</a>
                      {s.target === 'sanitized' && <span className="muted"> (verification re-scan)</span>}
                    </td>
                    <td data-label="Verdict"><StatusPill status={verdictStatus(s.verdict)} size="sm" /></td>
                    <td data-label="Dataset now"><StatusPill status={s.dataset_status} size="sm" /></td>
                    <td data-label="Threat intel"><ToneChip tone={ENRICHMENT_TONE[s.enrichment_status] ?? 'neutral'}>{enrichmentLabel(s.enrichment_status)}</ToneChip></td>
                    <td data-label="Coverage">{s.coverage_status === 'FULL' ? 'Full' : <ToneChip tone="risk">{s.coverage_status.toLowerCase()}</ToneChip>}</td>
                    <td data-label="Findings" className="is-numeric">{s.threats_found_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <nav className="pager" aria-label="Scan history pages">
            <Button variant="ghost" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>Newer</Button>
            <span className="muted" aria-live="polite">Page {page} of {pages} ({data.total} scan{data.total === 1 ? '' : 's'})</span>
            <Button variant="ghost" disabled={page >= pages} onClick={() => setPage((p) => p + 1)}>Older</Button>
          </nav>
        </>
      )}
      {state === 'ready' && data.total > 0 && <p className="muted table-note">The verdict is what that scan decided. "Dataset now" is the dataset's current status, which can change after a later scan or remediation.</p>}
    </Card>
  );
}
