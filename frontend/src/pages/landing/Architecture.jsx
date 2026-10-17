/**
 * The real scan pipeline (backend/routers/datasets.py, scanner/engine.py,
 * services/threat_intelligence/enrichment.py, services/llm_service.py,
 * routers/remediation.py) as an SVG flow. Solid boxes decide the verdict; dashed
 * boxes only add context.
 */
const NODES = [
  { id: 'upload', x: 0, y: 0, title: 'Upload', sub: 'SHA-256, size cap, magic bytes' },
  { id: 'av', x: 1, y: 0, title: 'Antivirus', sub: 'ClamAV or hash lookup' },
  { id: 'heur', x: 2, y: 0, title: 'Heuristics + YARA', sub: '9 heuristics, 4 rules' },
  { id: 'cells', x: 3, y: 0, title: 'Content rules', sub: '22 rules on every cell' },
  { id: 'verdict', x: 3, y: 1, title: 'Verdict', sub: 'deterministic, 0 to 10 risk' },
  { id: 'ti', x: 2, y: 1, title: 'Threat intel', sub: 'opt-in, evidence only', advisory: true },
  { id: 'ai', x: 1, y: 1, title: 'LLM analysis', sub: 'guardrailed, no raw cells', advisory: true },
  { id: 'fix', x: 0, y: 1, title: 'Remediate + re-scan', sub: 'one-time download' },
];
const EDGES = [['upload', 'av'], ['av', 'heur'], ['heur', 'cells'], ['cells', 'verdict'], ['verdict', 'ti'], ['ti', 'ai'], ['ai', 'fix']];

const W = 200;
const H = 84;
const GX = 240;
const GY = 150;

const pos = Object.fromEntries(NODES.map((n) => [n.id, { cx: n.x * GX + W / 2, cy: n.y * GY + H / 2 }]));

export default function Architecture() {
  return (
    <figure className="arch">
      <svg viewBox={`-10 -10 ${GX * 3 + W + 20} ${GY + H + 20}`} role="img" aria-labelledby="arch-title arch-desc">
        <title id="arch-title">Aegis Node scan pipeline</title>
        <desc id="arch-desc">
          Upload, antivirus, heuristics and YARA, then 22 content rules decide the verdict. Threat intelligence and
          the LLM analysis add context only. Remediation produces a copy that is scanned again.
        </desc>
        <defs>
          <marker id="arch-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0,0 L10,5 L0,10 z" className="arch__arrowhead" />
          </marker>
        </defs>
        {EDGES.map(([a, b]) => {
          const p = pos[a];
          const q = pos[b];
          const horizontal = Math.abs(p.cy - q.cy) < 1;
          const x1 = horizontal ? p.cx + Math.sign(q.cx - p.cx) * (W / 2) : p.cx;
          const y1 = horizontal ? p.cy : p.cy + H / 2;
          const x2 = horizontal ? q.cx - Math.sign(q.cx - p.cx) * (W / 2 + 4) : q.cx;
          const y2 = horizontal ? q.cy : q.cy - H / 2 - 4;
          return <line key={`${a}-${b}`} x1={x1} y1={y1} x2={x2} y2={y2} className="arch__edge" markerEnd="url(#arch-arrow)" />;
        })}
        {NODES.map((n) => (
          <g key={n.id} transform={`translate(${n.x * GX} ${n.y * GY})`} className={n.advisory ? 'arch__node arch__node--advisory' : 'arch__node'}>
            <rect width={W} height={H} rx="4" />
            <text x="16" y="34" className="arch__title">{n.title}</text>
            <text x="16" y="58" className="arch__sub">{n.sub}</text>
          </g>
        ))}
      </svg>
      {/* Narrow screens: the same pipeline as a list, because the diagram text would be unreadable */}
      <ol className="arch__list">
        {NODES.map((n) => (
          <li key={n.id} className={n.advisory ? 'is-advisory' : undefined}>
            <strong>{n.title}</strong> <span className="muted">{n.sub}{n.advisory ? ' (context only)' : ''}</span>
          </li>
        ))}
      </ol>
      <figcaption className="muted">Solid: decides the verdict. Dashed: adds context, never changes the verdict.</figcaption>
    </figure>
  );
}
