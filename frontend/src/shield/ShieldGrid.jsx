import { useEffect, useMemo, useState } from 'react';
import { statusToPlate } from '../status/statusToPlate';
import { buildPlates } from './layout';
import { plateLook, readTokens } from './tones';

const R = 1; // hex radius in layout units

function hexPoints(cx, cy) {
  return Array.from({ length: 6 }, (_, i) => {
    const a = (Math.PI / 3) * i;
    return `${(cx + R * 0.94 * Math.cos(a)).toFixed(3)},${(cy + R * 0.94 * Math.sin(a)).toFixed(3)}`;
  }).join(' ');
}

/**
 * 2D plate grid: the static shield shown before the 3D canvas loads, on phones,
 * without WebGL, and with reduced motion. Real plates are links to the dataset;
 * filler plates are drawn but not interactive.
 */
export default function ShieldGrid({ datasets, interactive = true, onSelect, selectedId, theme }) {
  const plates = useMemo(() => buildPlates(datasets), [datasets]);
  const [tokens, setTokens] = useState(null);
  useEffect(() => { setTokens(readTokens()); }, [theme]);

  const xs = plates.map((p) => p.x);
  const ys = plates.map((p) => p.y);
  const pad = 1.2;
  const viewBox = `${Math.min(...xs) - pad} ${Math.min(...ys) - pad} ${Math.max(...xs) - Math.min(...xs) + pad * 2} ${Math.max(...ys) - Math.min(...ys) + pad * 2}`;

  return (
    <svg className="shield-grid" viewBox={viewBox} role={interactive ? 'group' : 'img'} aria-label={interactive ? 'Dataset plates' : 'Aegis shield'}>
      {plates.map((p) => {
        const look = tokens ? plateLook(p, tokens) : { kind: p.dataset ? 'unscanned' : 'filler', color: 'currentColor' };
        const poly = (
          <polygon
            points={hexPoints(p.x, p.y)}
            className={`shield-grid__plate shield-grid__plate--${look.kind}${p.dataset && p.dataset.dataset_id === selectedId ? ' is-selected' : ''}`}
            style={{ '--plate': look.color }}
          />
        );
        if (!p.dataset || !interactive) return <g key={p.key} aria-hidden="true">{poly}</g>;
        const s = statusToPlate(p.dataset.shown);
        return (
          <a
            key={p.key}
            href={`#/app/datasets/${p.dataset.dataset_id}`}
            onClick={onSelect ? (e) => { e.preventDefault(); onSelect(p.dataset); } : undefined}
            aria-label={`${p.dataset.original_filename}: ${s.label}`}
          >
            <title>{`${p.dataset.original_filename}: ${s.label}`}</title>
            {poly}
          </a>
        );
      })}
    </svg>
  );
}
