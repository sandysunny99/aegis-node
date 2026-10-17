import { useEffect, useState } from 'react';
import { DATASET_STATUSES, statusToPlate } from '../status/statusToPlate';
import Button from '../ui/Button';
import Card from '../ui/Card';
import Icon from '../ui/Icon';
import Skeleton from '../ui/Skeleton';
import StatusPill from '../ui/StatusPill';
import Table from '../ui/Table';
import ThemeToggle from '../ui/ThemeToggle';
import Tooltip from '../ui/Tooltip';
import { SAMPLE_ROWS } from './styleguide.fixtures';

const COLOR_GROUPS = [
  ['Surfaces', ['--surface-inset', '--surface-base', '--surface-raised', '--surface-overlay', '--line', '--line-strong']],
  ['Text', ['--text-primary', '--text-secondary', '--text-muted', '--text-inverse']],
  ['Accent (one)', ['--accent', '--accent-strong', '--accent-edge', '--on-accent']],
  ['Status', ['--status-clean', '--status-risk', '--status-breach', '--status-scanning', '--status-neutral', '--status-breach-fill']],
];
const TYPE_STEPS = ['--step-5', '--step-4', '--step-3', '--step-2', '--step-1', '--step-0', '--step--1'];
const SPACE_STEPS = ['--space-1', '--space-2', '--space-3', '--space-4', '--space-6', '--space-8', '--space-12', '--space-16', '--space-24'];

/** Read token values from the live stylesheet so the page always shows what ships. */
function useTokenValues(names, theme) {
  const [values, setValues] = useState({});
  useEffect(() => {
    const css = getComputedStyle(document.documentElement);
    setValues(Object.fromEntries(names.map((n) => [n, css.getPropertyValue(n).trim()])));
  }, [names, theme]);
  return values;
}

const ALL_COLORS = COLOR_GROUPS.flatMap(([, names]) => names);

export default function Styleguide({ theme, onThemeChange }) {
  const colors = useTokenValues(ALL_COLORS, theme);
  const space = useTokenValues(SPACE_STEPS, theme);

  return (
    <div className="sg">
      <header className="sg__header">
        <div>
          <h1>Bastion styleguide</h1>
          <p className="sg__lede">Every token, status and component state used by the Aegis Node interface.</p>
        </div>
        <div className="sg__header-actions">
          <a href="#/">Back to the app</a>
          <ThemeToggle theme={theme} onChange={onThemeChange} />
        </div>
      </header>

      <main id="main" className="sg__main">
        <Card title="Colour tokens" id="sg-colors">
          {COLOR_GROUPS.map(([group, names]) => (
            <div key={group} className="sg__group">
              <h3 className="sg__group-title">{group}</h3>
              <ul className="sg__swatches">
                {names.map((n) => (
                  <li key={n} className="sg__swatch">
                    <span className="sg__chip" style={{ background: `var(${n})` }} aria-hidden="true" />
                    <span className="mono">{n}</span>
                    <span className="mono sg__value">{colors[n]}</span>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </Card>

        <Card title="Type scale (1.25, IBM Plex Sans / IBM Plex Mono)" id="sg-type">
          <ul className="sg__type">
            {TYPE_STEPS.map((s) => (
              <li key={s}>
                <span className="mono sg__value">{s}</span>
                <span style={{ fontSize: `var(${s})` }}>Scan a dataset before it reaches training</span>
              </li>
            ))}
            <li>
              <span className="mono sg__value">--font-mono</span>
              <span className="mono">sha256 9f2c4a1e7b03d5c8 · 18,204 rows · 2026-10-17 06:45</span>
            </li>
          </ul>
        </Card>

        <Card title="Spacing (4px base), radius, chamfer, elevation" id="sg-shape">
          <ul className="sg__space">
            {SPACE_STEPS.map((s) => (
              <li key={s}>
                <span className="mono sg__value">{s} = {space[s]}</span>
                <span className="sg__bar" style={{ width: `var(${s})` }} aria-hidden="true" />
              </li>
            ))}
          </ul>
          <div className="sg__shapes">
            <div className="sg__shape sg__shape--radius">--radius (surfaces, inputs)</div>
            <div className="sg__shape sg__shape--chamfer">--chamfer (plate motif)</div>
            <div className="sg__shape sg__shape--hex" aria-hidden="true" />
            <div className="sg__shape sg__elev" style={{ boxShadow: 'var(--shadow-resting)' }}>resting</div>
            <div className="sg__shape sg__elev" style={{ boxShadow: 'var(--shadow-raised)' }}>raised</div>
            <div className="sg__shape sg__elev" style={{ boxShadow: 'var(--shadow-pressed)' }}>pressed</div>
          </div>
        </Card>

        <Card title="Statuses (11 backend values, one shared map)" id="sg-status">
          <ul className="sg__statuses">
            {DATASET_STATUSES.map((s) => (
              <li key={s}>
                <StatusPill status={s} />
                <span className="mono sg__value">{s} → plate “{statusToPlate(s).plate}”</span>
              </li>
            ))}
          </ul>
        </Card>

        <Card title="PlateButton" id="sg-buttons">
          {['primary', 'secondary', 'danger', 'ghost'].map((v) => (
            <div key={v} className="sg__row">
              <span className="mono sg__value sg__row-label">{v}</span>
              <Button variant={v} onClick={() => {}}>Scan dataset</Button>
              <Button variant={v} disabled>Scan dataset</Button>
              <Button variant={v} loading>Scan dataset</Button>
            </div>
          ))}
          <p className="sg__note">Columns: default, disabled, loading. Hover lifts the face, press drops it 4px onto the edge, Tab shows the accent focus ring.</p>
        </Card>

        <Card title="Table, tooltip, skeleton, notices" id="sg-misc">
          <Table
            caption="Sample datasets (styleguide fixtures)"
            rowKey={(r) => r.id}
            columns={[
              { key: 'status', header: 'Status', render: (r) => <StatusPill status={r.status} size="sm" /> },
              { key: 'name', header: 'Name' },
              { key: 'id', header: 'ID', mono: true, render: (r) => r.id.slice(0, 12) },
              { key: 'size', header: 'Size', numeric: true },
              { key: 'flagged', header: 'Flagged', numeric: true, render: (r) => (r.flagged ?? '–') },
            ]}
            rows={SAMPLE_ROWS}
          />
          <div className="sg__row sg__row--gap">
            <Tooltip content="sample_quarantined.csv · Quarantined · last scan 06:45">
              <button type="button" className="icon-btn" aria-label="Plate details">
                <Icon name="ShieldX" size={18} />
              </button>
            </Tooltip>
            <span className="sg__skeleton-row" aria-label="Loading example">
              <Skeleton width="120px" height="12px" />
              <Skeleton width="220px" height="12px" />
              <Skeleton width="64px" height="12px" />
            </span>
          </div>
          <div className="sg__stack">
            <div className="notice notice--error" role="alert">
              <Icon name="CircleAlert" className="notice__icon" />
              <span>Scan failed: the file could not be read. Upload it again or choose another file.</span>
            </div>
            <div className="notice notice--risk">
              <Icon name="ShieldMinus" className="notice__icon" />
              <span>Limited scan: YARA was unavailable (DETECTOR_UNAVAILABLE:yara), so this result is not fully verified.</span>
            </div>
          </div>
        </Card>
      </main>
    </div>
  );
}
