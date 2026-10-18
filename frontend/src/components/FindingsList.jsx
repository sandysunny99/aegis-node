import { plainDashes } from '../status/text';

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4, informational: 4 };

export default function FindingsList({ findings }) {
  if (!findings || findings.length === 0) {
    return <p className="empty">The scanner reported no findings for this dataset.</p>;
  }

  const sorted = [...findings].sort(
    (a, b) => (SEVERITY_ORDER[a.severity?.toLowerCase()] ?? 5) - (SEVERITY_ORDER[b.severity?.toLowerCase()] ?? 5),
  );

  return (
    <ul className="findings" aria-label={`${findings.length} findings`}>
      {sorted.map((f, i) => {
        const sev = (f.severity || 'unknown').toLowerCase();
        return (
          <li key={`${f.rule_id}-${f.location}-${i}`} className="finding">
            <div className="finding__top">
              <span className={`finding__sev finding__sev--${sev}`}>{sev}</span>
              <span className="finding__rule">{f.rule_id}</span>
            </div>
            <p>{plainDashes(f.description)}</p>
            {f.location && <p className="finding__loc">Location: {f.location}</p>}
          </li>
        );
      })}
    </ul>
  );
}
