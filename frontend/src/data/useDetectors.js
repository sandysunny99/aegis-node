import { useEffect, useState } from 'react';
import { getDetectors } from '../api';

// One request per page load; every panel that lists providers shares it.
let pending = null;

/**
 * GET /health/detectors `detectors`, or null while loading and on servers without the
 * route (older backends). With null, provider lists fall back to the providers named in
 * the report itself (status/layers.js providerList), so nothing checked is hidden.
 */
export function useDetectors() {
  const [catalog, setCatalog] = useState(null);
  useEffect(() => {
    let live = true;
    pending ??= getDetectors().then((r) => (Array.isArray(r?.detectors) ? r.detectors : null)).catch(() => null);
    pending.then((c) => { if (live) setCatalog(c); });
    return () => { live = false; };
  }, []);
  return catalog;
}
