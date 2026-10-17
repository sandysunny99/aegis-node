import { useCallback, useEffect, useState } from 'react';
import { getHistory } from '../api';
import { byUrgency, effectiveStatus } from '../status/statusToPlate';
import Button from '../ui/Button';
import Card from '../ui/Card';
import Icon from '../ui/Icon';
import Skeleton from '../ui/Skeleton';
import StatusPill from '../ui/StatusPill';
import Table from '../ui/Table';

const formatTime = (iso) => (iso ? new Date(iso).toLocaleString() : 'not scanned');

export default function HistoryPage() {
  const [items, setItems] = useState([]);
  const [state, setState] = useState('loading'); // loading | ready | error
  const [error, setError] = useState('');

  const load = useCallback(() => {
    setState('loading');
    getHistory(1, 50)
      .then((data) => { setItems(data.items || []); setState('ready'); })
      .catch((err) => { setError(err.message); setState('error'); });
  }, []);

  useEffect(load, [load]);

  const rows = items
    .map((item) => ({ ...item, shown: effectiveStatus(item.status, item.verdict) }))
    .sort((a, b) => byUrgency(a.shown, b.shown));

  return (
    <div id="panel-history" role="tabpanel" aria-labelledby="tab-history">
      <Card title="Datasets scanned from this browser" id="history">
        {state === 'loading' && (
          <div className="stack-sm" aria-label="Loading scan history">
            {[0, 1, 2].map((i) => <Skeleton key={i} height="44px" />)}
          </div>
        )}
        {state === 'error' && (
          <div className="error-banner" role="alert">
            <Icon name="CircleAlert" />
            <span>Scan history could not be loaded: {error}</span>
            <Button variant="ghost" onClick={load}>Retry</Button>
          </div>
        )}
        {state === 'ready' && rows.length === 0 && (
          <p className="empty">No datasets have been uploaded from this browser yet. Use the Scan a dataset tab to add one.</p>
        )}
        {state === 'ready' && rows.length > 0 && (
          <Table
            caption="Scan history, most urgent first"
            rowKey={(r) => r.dataset_id}
            columns={[
              { key: 'shown', header: 'Status', render: (r) => <StatusPill status={r.shown} size="sm" /> },
              { key: 'original_filename', header: 'Name', render: (r) => <span className="break">{r.original_filename}</span> },
              { key: 'scanned_at', header: 'Last scan', render: (r) => formatTime(r.scanned_at) },
              { key: 'threats_found_count', header: 'Findings', numeric: true, render: (r) => r.threats_found_count ?? 'not scanned' },
              { key: 'risk_score', header: 'Risk', numeric: true, render: (r) => (r.risk_score == null ? 'not scanned' : r.risk_score.toFixed(1)) },
            ]}
            rows={rows}
          />
        )}
      </Card>
    </div>
  );
}
