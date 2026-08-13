import React from 'react';

const VERDICT_CONFIG = {
  clean:     { label: 'Clean',     icon: '✅', cls: 'verdict-clean',      glow: 'var(--emerald)' },
  suspicious:{ label: 'Suspicious',icon: '⚠️', cls: 'verdict-suspicious', glow: 'var(--amber)' },
  malicious: { label: 'Malicious', icon: '🚨', cls: 'verdict-malicious',  glow: 'var(--rose)' },
};

export default function StatusBadge({ verdict = 'clean' }) {
  const cfg = VERDICT_CONFIG[verdict] || VERDICT_CONFIG.clean;
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
