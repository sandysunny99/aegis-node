import React from 'react';

export default function RiskMeter({ score = 0, verdict = 'clean' }) {
  const clampedScore = Math.min(10, Math.max(0, score));

  // Determine verdict color & label
  let color = 'var(--emerald)';
  let bg = 'rgba(16,185,129,0.1)';
  let level = 'LOW RISK';

  if (clampedScore >= 6.0 || verdict === 'malicious') {
    color = 'var(--rose)';
    bg = 'rgba(244,63,94,0.12)';
    level = 'HIGH RISK / MALICIOUS';
  } else if (clampedScore >= 3.0 || verdict === 'suspicious') {
    color = 'var(--amber)';
    bg = 'rgba(245,158,11,0.12)';
    level = 'MODERATE RISK';
  }

  const scorePct = Math.round((clampedScore / 10) * 100);

  return (
    <div
      style={{
        background: 'var(--bg-3)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--r-md)',
        padding: '1.25rem',
        minWidth: '220px',
        display: 'flex',
        flexDirection: 'column',
        gap: '0.75rem',
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span style={{ fontSize: '0.72rem', color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 700 }}>
          Threat Score
        </span>
        <span
          style={{
            padding: '0.2rem 0.5rem',
            background: bg,
            color,
            borderRadius: 'var(--r-full)',
            fontSize: '0.68rem',
            fontFamily: 'var(--mono)',
            fontWeight: 700,
            letterSpacing: '0.04em',
          }}
        >
          {level}
        </span>
      </div>

      <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.4rem' }}>
        <span style={{ fontSize: '2.5rem', fontWeight: 800, fontFamily: 'var(--mono)', color, lineHeight: 1 }}>
          {clampedScore.toFixed(1)}
        </span>
        <span style={{ fontSize: '0.85rem', color: 'var(--text-3)', fontFamily: 'var(--mono)' }}>
          / 10.0
        </span>
      </div>

      {/* Linear progress gauge */}
      <div style={{ width: '100%' }}>
        <div style={{
          height: '8px',
          background: 'var(--bg-0)',
          borderRadius: '9999px',
          overflow: 'hidden',
          position: 'relative',
        }}>
          <div style={{
            height: '100%',
            width: `${Math.max(scorePct, 4)}%`,
            background: color,
            borderRadius: '9999px',
            transition: 'width 0.6s ease',
            boxShadow: `0 0 10px ${color}`,
          }} />
        </div>

        {/* Scale indicators */}
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          marginTop: '0.35rem',
          fontSize: '0.65rem',
          color: 'var(--text-3)',
          fontFamily: 'var(--mono)',
        }}>
          <span>0.0 (Clean)</span>
          <span>5.0</span>
          <span>10.0 (Malicious)</span>
        </div>
      </div>
    </div>
  );
}

