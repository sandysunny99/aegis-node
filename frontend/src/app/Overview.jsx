import { formatTime } from '../data/useDatasets';
import Shield from '../shield/Shield';
import { DATASET_STATUSES, byUrgency, statusToPlate } from '../status/statusToPlate';
import Button from '../ui/Button';
import Card from '../ui/Card';
import Icon from '../ui/Icon';
import Skeleton from '../ui/Skeleton';
import StatusPill from '../ui/StatusPill';

const openDataset = (d) => { window.location.hash = `/app/datasets/${d.dataset_id}`; };

function StatusSummary({ datasets }) {
  const counts = DATASET_STATUSES
    .map((s) => [s, datasets.filter((d) => d.shown === s).length])
    .filter(([, n]) => n > 0)
    .sort(([a], [b]) => byUrgency(a, b));
  return (
    <ul className="summary-row" aria-label="Datasets by status">
      <li className="summary-row__total">
        <span className="summary-row__num mono">{datasets.length}</span>
        <span className="muted">dataset{datasets.length === 1 ? '' : 's'}</span>
      </li>
      {counts.map(([s, n]) => (
        <li key={s}>
          <span className="summary-row__num mono">{n}</span>
          <StatusPill status={s} size="sm" />
        </li>
      ))}
    </ul>
  );
}

export default function Overview({ datasets, state, error, reload, theme }) {
  if (state === 'loading') {
    return (
      <div className="overview">
        <Skeleton height="64px" />
        <div className="overview__grid">
          <Skeleton height="360px" />
          <Skeleton height="360px" />
        </div>
      </div>
    );
  }
  if (state === 'error') {
    return (
      <div className="error-banner" role="alert">
        <Icon name="CircleAlert" />
        <span>Your datasets could not be loaded: {error}</span>
        <Button variant="ghost" onClick={reload}>Retry</Button>
      </div>
    );
  }
  if (datasets.length === 0) {
    return (
      <Card title="No datasets yet" id="overview-empty" className="empty-card">
        <p className="muted">
          Each dataset you upload from this browser becomes one plate on the shield. Upload a CSV, JSON, JSONL,
          Parquet, XLSX or TXT file to scan it.
        </p>
        <div className="btn-row">
          <Button variant="primary" onClick={() => { window.location.hash = '/app/scan'; }}>Scan a dataset</Button>
        </div>
      </Card>
    );
  }

  const recent = [...datasets]
    .filter((d) => d.scanned_at)
    .sort((a, b) => new Date(b.scanned_at) - new Date(a.scanned_at))
    .slice(0, 6);

  return (
    <div className="overview">
      <StatusSummary datasets={datasets} />
      <div className="overview__grid">
        <Card title="Shield" id="overview-shield" className="overview__shield">
          <p className="muted card-lede">One plate per dataset. Hover for details, click to open it.</p>
          <Shield datasets={[...datasets].sort((a, b) => byUrgency(a.shown, b.shown))} mode="compact" theme={theme} onSelect={openDataset} />
        </Card>
        <Card title="Recent scans" id="overview-recent">
          {recent.length === 0 ? (
            <p className="empty">Nothing has been scanned yet.</p>
          ) : (
            <ul className="recent">
              {recent.map((d) => (
                <li key={d.dataset_id}>
                  <a href={`#/app/datasets/${d.dataset_id}`} className="recent__name break">{d.original_filename}</a>
                  <StatusPill status={d.shown} size="sm" />
                  <span className="muted mono recent__time">{formatTime(d.scanned_at)}</span>
                  <span className="muted recent__findings">
                    {d.threats_found_count ?? 0} finding{d.threats_found_count === 1 ? '' : 's'}
                    {statusToPlate(d.shown).plate === 'breached' ? ', quarantined automatically' : ''}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </div>
  );
}
