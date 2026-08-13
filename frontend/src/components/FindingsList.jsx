import React from 'react';

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

const SEV_COLORS = {
  critical: 'var(--rose)',
  high: 'var(--amber)',
  medium: 'var(--blue)',
  low: 'var(--purple)',
};

const CATEGORY_ICONS = {
  formula_injection: '⚡',
  script_injection: '💉',
  sql_injection: '🛢️',
  binary_anomaly: '⚠️',
  clamav: '🦠',
};

export default function FindingsList({ findings = [] }) {
  const sorted = [...findings].sort((a, b) =>
    (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4)
  );

  const counts = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {});

  if (findings.length === 0) {
    return null;
  }

  return (
    <div>
      {/* Severity summary pills */}
      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '1rem' }}>
        {Object.entries(counts).sort((a, b) => SEVERITY_ORDER[a[0]] - SEVERITY_ORDER[b[0]]).map(([sev, count]) => (
          <span key={sev} style={{
            padding: '0.2rem 0.75rem',
            background: `${SEV_COLORS[sev]}18`,
            border: `1px solid ${SEV_COLORS[sev]}40`,
            borderRadius: '9999px',
            fontSize: '0.75rem',
            fontWeight: 700,
            color: SEV_COLORS[sev],
            letterSpacing: '0.04em',
            textTransform: 'uppercase',
          }}>
            {count} {sev}
          </span>
        ))}
      </div>

      <div className="findings-header">
        <span style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-2)', letterSpacing: '0.06em', textTransform: 'uppercase' }}>
          Threat Findings
        </span>
        <span className="findings-count">{findings.length} issue{findings.length !== 1 ? 's' : ''} found</span>
      </div>

      <div className="findings-list">
        {sorted.map((f, i) => (
          <FindingItem key={i} finding={f} index={i} />
        ))}
      </div>
    </div>
  );
}

function FindingItem({ finding, index }) {
  const [expanded, setExpanded] = React.useState(false);
  const color = SEV_COLORS[finding.severity] || 'var(--text-3)';
  const icon = CATEGORY_ICONS[finding.category] || '🔍';

  return (
    <div
      className={`finding-item sev-${finding.severity} fade-in`}
      style={{ animationDelay: `${index * 0.04}s`, cursor: 'pointer' }}
      onClick={() => setExpanded(x => !x)}
    >
      <div className="finding-top">
        <span style={{ fontSize: '1rem', flexShrink: 0 }}>{icon}</span>
        <span className={`sev-pill ${finding.severity}`}>{finding.severity}</span>
        <span className="finding-desc">{finding.description}</span>
        <span style={{ color: 'var(--text-3)', fontSize: '0.75rem', flexShrink: 0, transition: 'transform 0.2s', transform: expanded ? 'rotate(180deg)' : 'none' }}>▾</span>
      </div>

      <div className="finding-meta">
        <span className="finding-rule" title="Rule ID">{finding.rule_id}</span>
        <span className="finding-loc" title="Location">
          📍 {finding.location}
        </span>
        <span style={{
          padding: '0.1rem 0.5rem',
          background: `${color}12`,
          border: `1px solid ${color}30`,
          borderRadius: '9999px',
          fontSize: '0.68rem',
          color,
          fontWeight: 600,
          textTransform: 'uppercase',
          letterSpacing: '0.06em',
        }}>
          {finding.category.replace(/_/g, ' ')}
        </span>
      </div>

      {expanded && finding.sample && (
        <div className="finding-sample fade-in">
          <span style={{ color: 'var(--text-3)', marginRight: '0.5rem', fontSize: '0.7rem' }}>SAMPLE:</span>
          {finding.sample}
        </div>
      )}
    </div>
  );
}
