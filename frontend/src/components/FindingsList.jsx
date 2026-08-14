import React, { useState } from 'react';

const SEVERITY_CONFIG = {
  critical: { label: 'Critical', color: 'var(--rose)', bg: 'rgba(244,63,94,0.12)', border: 'rgba(244,63,94,0.3)', icon: '🚨' },
  high:     { label: 'High',     color: 'var(--amber)', bg: 'rgba(245,158,11,0.12)', border: 'rgba(245,158,11,0.3)', icon: '⚠️' },
  medium:   { label: 'Medium',   color: 'var(--blue)',  bg: 'rgba(59,130,246,0.12)', border: 'rgba(59,130,246,0.3)', icon: '⚡' },
  low:      { label: 'Low',      color: 'var(--purple)', bg: 'rgba(139,92,246,0.12)', border: 'rgba(139,92,246,0.3)', icon: 'ℹ️' },
};

const CATEGORY_ICONS = {
  malware_signature: '🦠',
  process_injection: '💉',
  shellcode: '⚡',
  obfuscation_packer: '📦',
  heuristic_entropy: '🎲',
  formula_injection: '📐',
  script_injection: '🛡️',
  sql_injection: '🛢️',
  binary_anomaly: '⚠️',
  clamav: '🦠',
};

export default function FindingsList({ findings = [] }) {
  if (findings.length === 0) {
    return null;
  }

  // Group findings by severity
  const grouped = {
    critical: [],
    high: [],
    medium: [],
    low: [],
  };

  findings.forEach((f) => {
    const sev = f.severity?.toLowerCase() || 'low';
    if (grouped[sev]) {
      grouped[sev].push(f);
    } else {
      grouped.low.push(f);
    }
  });

  return (
    <div style={{ marginTop: '1.25rem' }}>
      <div className="findings-header">
        <span style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--text-1)', letterSpacing: '0.04em', textTransform: 'uppercase' }}>
          🛡️ Threat Detection Findings
        </span>
        <span className="findings-count" style={{ fontFamily: 'var(--mono)', fontSize: '0.8rem', color: 'var(--text-2)' }}>
          {findings.length} total issue{findings.length !== 1 ? 's' : ''} identified
        </span>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.875rem' }}>
        {Object.entries(SEVERITY_CONFIG).map(([sev, config]) => {
          const items = grouped[sev];
          if (items.length === 0) return null;
          return <SeverityGroup key={sev} severity={sev} config={config} items={items} />;
        })}
      </div>
    </div>
  );
}

function SeverityGroup({ severity, config, items }) {
  const [open, setOpen] = useState(true);

  return (
    <div style={{
      background: 'var(--bg-3)',
      border: `1px solid ${config.border}`,
      borderRadius: 'var(--r-md)',
      overflow: 'hidden',
      transition: 'all 0.2s',
    }}>
      {/* Group Header Bar */}
      <button
        onClick={() => setOpen(o => !o)}
        aria-expanded={open}
        style={{
          width: '100%',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '0.75rem 1rem',
          background: config.bg,
          border: 'none',
          cursor: 'pointer',
          color: config.color,
          fontFamily: 'var(--font)',
          fontWeight: 700,
          fontSize: '0.85rem',
          letterSpacing: '0.04em',
          textTransform: 'uppercase',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}>
          <span>{config.icon}</span>
          <span>{config.label} Severity</span>
          <span style={{
            padding: '0.15rem 0.6rem',
            background: `${config.color}24`,
            borderRadius: '9999px',
            fontSize: '0.72rem',
            color: config.color,
            fontFamily: 'var(--mono)',
          }}>
            {items.length}
          </span>
        </div>
        <span style={{
          transform: open ? 'rotate(180deg)' : 'none',
          transition: 'transform 0.2s',
          fontSize: '0.8rem',
        }}>
          ▼
        </span>
      </button>

      {/* Group Content */}
      {open && (
        <div style={{ padding: '0.75rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          {items.map((item, idx) => (
            <FindingCard key={idx} finding={item} config={config} index={idx} />
          ))}
        </div>
      )}
    </div>
  );
}

function FindingCard({ finding, config, index }) {
  const [expanded, setExpanded] = useState(false);
  const catIcon = CATEGORY_ICONS[finding.category] || '🔍';

  return (
    <div
      className="fade-in"
      style={{
        background: 'var(--bg-2)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--r-sm)',
        padding: '0.75rem 1rem',
        borderLeft: `4px solid ${config.color}`,
        animationDelay: `${index * 0.03}s`,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '0.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.625rem', flex: 1 }}>
          <span style={{ fontSize: '1.1rem', marginTop: '1px' }}>{catIcon}</span>
          <div style={{ flex: 1 }}>
            <div style={{ fontWeight: 600, fontSize: '0.875rem', color: 'var(--text-1)', lineHeight: 1.4 }}>
              {finding.description}
            </div>
            {/* Meta Tags */}
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginTop: '0.4rem', alignItems: 'center' }}>
              <span style={{
                fontFamily: 'var(--mono)',
                fontSize: '0.72rem',
                color: 'var(--cyan)',
                background: 'rgba(6,182,212,0.1)',
                padding: '0.15rem 0.45rem',
                borderRadius: '4px',
                border: '1px solid rgba(6,182,212,0.25)',
              }}>
                {finding.rule_id}
              </span>
              <span style={{
                fontSize: '0.72rem',
                color: 'var(--text-2)',
                background: 'var(--bg-0)',
                padding: '0.15rem 0.5rem',
                borderRadius: '4px',
                border: '1px solid var(--border)',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.25rem',
              }}>
                📍 {finding.location}
              </span>
              <span style={{
                fontSize: '0.7rem',
                color: 'var(--text-3)',
                textTransform: 'uppercase',
                letterSpacing: '0.04em',
              }}>
                {finding.category.replace(/_/g, ' ')}
              </span>
            </div>
          </div>
        </div>

        {finding.sample && (
          <button
            onClick={() => setExpanded(e => !e)}
            aria-label="Toggle sample snippet"
            style={{
              background: 'none',
              border: 'none',
              color: 'var(--cyan)',
              fontSize: '0.78rem',
              cursor: 'pointer',
              padding: '0.25rem',
              fontFamily: 'var(--font)',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.25rem',
            }}
          >
            {expanded ? 'Hide Sample' : 'View Sample'}
          </button>
        )}
      </div>

      {expanded && finding.sample && (
        <div className="fade-in" style={{
          marginTop: '0.625rem',
          background: 'rgba(0,0,0,0.4)',
          border: '1px solid rgba(255,255,255,0.06)',
          borderRadius: 'var(--r-sm)',
          padding: '0.5rem 0.75rem',
          fontSize: '0.75rem',
          fontFamily: 'var(--mono)',
          color: 'var(--amber)',
          wordBreak: 'break-all',
        }}>
          <span style={{ color: 'var(--text-3)', fontSize: '0.68rem', marginRight: '0.5rem' }}>EVIDENCE:</span>
          {finding.sample}
        </div>
      )}
    </div>
  );
}

