import React from 'react';

const SCORE_COLORS = [
  [0, 2,   'var(--emerald)'],
  [2, 4,   '#4ade80'],
  [4, 6,   'var(--amber)'],
  [6, 8,   '#fb923c'],
  [8, 10,  'var(--rose)'],
];

function getColor(score) {
  for (const [lo, hi, color] of SCORE_COLORS) {
    if (score >= lo && score < hi) return color;
  }
  return 'var(--rose)';
}

/**
 * SVG half-circle arc risk meter.
 * Score range: 0–10
 */
export default function RiskMeter({ score = 0, verdict = 'clean' }) {
  const clampedScore = Math.min(10, Math.max(0, score));
  const color = getColor(clampedScore);

  // Arc geometry
  const W = 200, H = 110;
  const cx = W / 2, cy = H - 10;
  const r = 82;
  const sweepAngle = 180; // degrees
  const startAngle = -180;
  const angle = startAngle + (clampedScore / 10) * sweepAngle;
  const rad = (deg) => (deg * Math.PI) / 180;

  // Background arc path (full semicircle)
  const bgPath = describeArc(cx, cy, r, -180, 0);
  // Filled arc path
  const fillPath = describeArc(cx, cy, r, -180, angle);

  // Needle tip position
  const needleRad = rad(angle);
  const nx = cx + r * Math.cos(needleRad);
  const ny = cy + r * Math.sin(needleRad);

  return (
    <div className="risk-meter" id="risk-meter">
      <div className="risk-arc-container" style={{ width: W, height: H }}>
        <svg width={W} height={H} viewBox={`0 0 ${W} ${H}`} overflow="visible">
          {/* Track */}
          <path d={bgPath} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="12" strokeLinecap="round" />

          {/* Colored arc (filled up to score) */}
          <path
            d={fillPath}
            fill="none"
            stroke={color}
            strokeWidth="12"
            strokeLinecap="round"
            style={{ filter: `drop-shadow(0 0 6px ${color}80)`, transition: 'stroke 0.4s' }}
          />

          {/* Needle */}
          <line
            x1={cx} y1={cy}
            x2={nx} y2={ny}
            stroke={color} strokeWidth="2.5" strokeLinecap="round"
            style={{ transition: 'all 0.5s ease', filter: `drop-shadow(0 0 4px ${color})` }}
          />
          <circle cx={cx} cy={cy} r={5} fill={color} style={{ filter: `drop-shadow(0 0 4px ${color})` }} />

          {/* Tick marks */}
          {[0,2,4,6,8,10].map(v => {
            const a = rad(-180 + (v / 10) * 180);
            const x1 = cx + (r - 16) * Math.cos(a), y1 = cy + (r - 16) * Math.sin(a);
            const x2 = cx + r * Math.cos(a), y2 = cy + r * Math.sin(a);
            return <line key={v} x1={x1} y1={y1} x2={x2} y2={y2} stroke="rgba(255,255,255,0.18)" strokeWidth="1.5" />;
          })}

          {/* Scale labels */}
          {[[0, 'low'], [5, 'mid'], [10, 'high']].map(([v, label]) => {
            const a = rad(-180 + (v / 10) * 180);
            const lx = cx + (r + 18) * Math.cos(a);
            const ly = cy + (r + 18) * Math.sin(a);
            return (
              <text key={v} x={lx} y={ly} textAnchor="middle" dominantBaseline="middle"
                fill="rgba(255,255,255,0.25)" fontSize="9" fontFamily="var(--mono)">
                {v}
              </text>
            );
          })}
        </svg>

        {/* Center score text */}
        <div className="risk-score-text">
          <div className="risk-score-value" style={{ color }}>
            {clampedScore.toFixed(1)}
          </div>
          <div className="risk-score-label">/ 10.0 risk</div>
        </div>
      </div>
    </div>
  );
}

// SVG arc path helper
function describeArc(cx, cy, r, startDeg, endDeg) {
  const s = polarToCartesian(cx, cy, r, startDeg);
  const e = polarToCartesian(cx, cy, r, endDeg);
  const largeArc = Math.abs(endDeg - startDeg) > 180 ? 1 : 0;
  return `M ${s.x} ${s.y} A ${r} ${r} 0 ${largeArc} 1 ${e.x} ${e.y}`;
}

function polarToCartesian(cx, cy, r, deg) {
  const rad = (deg * Math.PI) / 180;
  return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) };
}
