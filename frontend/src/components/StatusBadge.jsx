import React from 'react';

const VERDICT_CONFIG = {
  clean_verified:         { label: 'Clean (Verified)',          icon: '🛡️', cls: 'verdict-clean',      glow: 'var(--emerald)' },
  clean_with_limitations: { label: 'Clean (With Limitations)',  icon: 'ℹ️',  cls: 'verdict-limited',    glow: 'var(--amber)' },
  clean:                  { label: 'Clean',                     icon: '✅', cls: 'verdict-clean',      glow: 'var(--emerald)' },
  suspicious:             { label: 'Suspicious',                icon: '⚠️', cls: 'verdict-suspicious', glow: 'var(--amber)' },
  malicious:              { label: 'Malicious',                 icon: '🚨', cls: 'verdict-malicious',  glow: 'var(--rose)' },
  scan_incomplete:        { label: 'Scan Incomplete',           icon: '⏳', cls: 'verdict-limited',    glow: 'var(--slate-400)' },
};

export default function StatusBadge({ verdict = 'clean_verified' }) {
  const cfg = VERDICT_CONFIG[verdict] || VERDICT_CONFIG[verdict?.toLowerCase()] || VERDICT_CONFIG.clean_verified;
  return (
    <div
      className={`verdict-badge ${cfg.cls}`}
      title={`Scan verdict: ${cfg.label}`}
      id="status-badge"
    >
      <span>{cfg.icon}</span>
      <span>{cfg.label}</span>
    </div>
  );
}
