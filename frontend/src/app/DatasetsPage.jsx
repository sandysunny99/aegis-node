import { useMemo, useState } from 'react';
import { formatBytes, formatTime } from '../data/useDatasets';
import { DATASET_STATUSES, byUrgency, statusToPlate } from '../status/statusToPlate';
import Button from '../ui/Button';
import Card from '../ui/Card';
import Icon from '../ui/Icon';
import Skeleton from '../ui/Skeleton';
import StatusPill from '../ui/StatusPill';

const COLUMNS = [
  { key: 'shown', label: 'Status', sort: (a, b) => byUrgency(a.shown, b.shown) },
  { key: 'original_filename', label: 'Name', sort: (a, b) => a.original_filename.localeCompare(b.original_filename) },
  { key: 'file_format', label: 'Format', sort: (a, b) => a.file_format.localeCompare(b.file_format) },
  { key: 'file_size_bytes', label: 'Size', numeric: true, sort: (a, b) => a.file_size_bytes - b.file_size_bytes },
  { key: 'scanned_at', label: 'Last scan', sort: (a, b) => new Date(a.scanned_at ?? 0) - new Date(b.scanned_at ?? 0) },
  { key: 'threats_found_count', label: 'Findings', numeric: true, sort: (a, b) => (a.threats_found_count ?? -1) - (b.threats_found_count ?? -1) },
  { key: 'dataset_id', label: 'ID', sort: (a, b) => a.dataset_id.localeCompare(b.dataset_id) },
];

function cell(d, key) {
  switch (key) {
    case 'shown': return <StatusPill status={d.shown} size="sm" />;
    case 'original_filename': return <a href={`#/app/datasets/${d.dataset_id}`} className="break">{d.original_filename}</a>;
    case 'file_format': return d.file_format.toUpperCase();
    case 'file_size_bytes': return formatBytes(d.file_size_bytes);
    case 'scanned_at': return formatTime(d.scanned_at);
    case 'threats_found_count': return d.threats_found_count ?? 'not scanned';
    case 'dataset_id': return <span className="mono">{d.dataset_id.slice(0, 12)}</span>;
    default: return d[key];
  }
}

export default function DatasetsPage({ datasets, state, error, reload }) {
  const [query, setQuery] = useState('');
  const [status, setStatus] = useState('all');
  const [sort, setSort] = useState({ key: 'shown', dir: 1 });

  const rows = useMemo(() => {
    const col = COLUMNS.find((c) => c.key === sort.key);
    return datasets
      .filter((d) => status === 'all' || d.shown === status)
      .filter((d) => d.original_filename.toLowerCase().includes(query.trim().toLowerCase()))
      .sort((a, b) => col.sort(a, b) * sort.dir);
  }, [datasets, query, status, sort]);

  const present = DATASET_STATUSES.filter((s) => datasets.some((d) => d.shown === s));
  const toggleSort = (key) => setSort((s) => (s.key === key ? { key, dir: -s.dir } : { key, dir: 1 }));

  return (
    <Card
      title="Datasets"
      id="datasets"
      actions={<Button variant="secondary" onClick={() => { window.location.hash = '/app/scan'; }}>Scan a dataset</Button>}
    >
      <div className="filters" role="search">
        <label className="filters__search">
          <span className="visually-hidden">Search by name</span>
          <Icon name="Search" size={16} />
          <input type="search" value={query} placeholder="Search by name" onChange={(e) => setQuery(e.target.value)} />
        </label>
        <label className="filters__status">
          <span>Status</span>
          <select className="select" value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="all">All statuses</option>
            {present.map((s) => <option key={s} value={s}>{statusToPlate(s).label}</option>)}
          </select>
        </label>
        <span className="muted" aria-live="polite">{state === 'ready' ? `${rows.length} of ${datasets.length}` : ''}</span>
      </div>

      {state === 'loading' && (
        <div className="stack-sm" aria-label="Loading datasets">
          {[0, 1, 2, 3].map((i) => <Skeleton key={i} height="48px" />)}
        </div>
      )}
      {state === 'error' && (
        <div className="error-banner" role="alert">
          <Icon name="CircleAlert" />
          <span>Datasets could not be loaded: {error}</span>
          <Button variant="ghost" onClick={reload}>Retry</Button>
        </div>
      )}
      {state === 'ready' && datasets.length === 0 && (
        <p className="empty">No datasets have been uploaded from this browser yet.</p>
      )}
      {state === 'ready' && datasets.length > 0 && rows.length === 0 && (
        <p className="empty">No dataset matches these filters.</p>
      )}
      {state === 'ready' && rows.length > 0 && (
        <div className="table-wrap">
          <table className="table">
            <caption className="visually-hidden">Datasets uploaded from this browser</caption>
            <thead>
              <tr>
                {COLUMNS.map((c) => (
                  <th
                    key={c.key}
                    scope="col"
                    className={c.numeric ? 'is-numeric' : undefined}
                    aria-sort={sort.key === c.key ? (sort.dir === 1 ? 'ascending' : 'descending') : 'none'}
                  >
                    <button type="button" className="th-sort" onClick={() => toggleSort(c.key)}>
                      {c.label}
                      <Icon name={sort.key !== c.key ? 'ArrowUpDown' : sort.dir === 1 ? 'ArrowUp' : 'ArrowDown'} size={14} />
                    </button>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((d) => (
                <tr key={d.dataset_id}>
                  {COLUMNS.map((c) => (
                    <td key={c.key} data-label={c.label} className={c.numeric ? 'is-numeric' : undefined}>{cell(d, c.key)}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="muted table-note">Row counts come from each scan report, so they are on the dataset's page. The API does not record where a dataset came from, so there is no source column.</p>
    </Card>
  );
}
