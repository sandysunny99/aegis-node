import { useCallback, useEffect, useState } from 'react';
import { getHistory } from '../api';
import { effectiveStatus } from '../status/statusToPlate';

/**
 * Datasets uploaded from this browser (GET /api/v1/history?ids=...).
 * Each item gets `shown`: the status to display, where the latest report verdict
 * wins over a legacy "clean" row.
 */
export function useDatasets() {
  const [items, setItems] = useState([]);
  const [state, setState] = useState('loading'); // loading | ready | error
  const [error, setError] = useState('');

  const reload = useCallback(() => {
    setState('loading');
    return getHistory(1, 100)
      .then((data) => {
        setItems((data.items || []).map((it) => ({ ...it, shown: effectiveStatus(it.status, it.verdict) })));
        setState('ready');
      })
      .catch((err) => {
        setError(err.message);
        setState('error');
      });
  }, []);

  useEffect(() => { reload(); }, [reload]);

  return { items, state, error, reload };
}

export function formatBytes(b) {
  if (!b) return '0 B';
  if (b < 1024) return `${b} B`;
  if (b < 1024 ** 2) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1024 ** 2).toFixed(1)} MB`;
}

export function formatTime(iso, empty = 'not scanned') {
  return iso ? new Date(iso).toLocaleString() : empty;
}
