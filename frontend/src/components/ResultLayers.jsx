import { detectorGaps } from '../status/limitations';
import { useDetectors } from '../data/useDetectors';
import { aiSummary, antivirusSummary, coverageSummary, enrichmentSummary, providerStates } from '../status/layers';
import { VERDICT_TO_STATUS } from '../status/statusToPlate';
import Card from '../ui/Card';
import StatusPill from '../ui/StatusPill';
import ToneChip from '../ui/ToneChip';

/**
 * The three result layers side by side, so a clean local scan with failed enrichment,
 * an incomplete scan and an unverified remediation never look alike.
 * `analysis` is undefined while loading, null when no analysis exists.
 */
export default function ResultLayers({ report, analysis }) {
  const coverage = coverageSummary(report);
  const gaps = detectorGaps(report.verification_limitations);
  const ti = enrichmentSummary(report.threat_intel);
  const detectors = useDetectors();
  const providers = providerStates(report.threat_intel, detectors);
  const avFallback = detectors?.find((d) => d.name === 'clamav')?.provider ?? null;
  const av = antivirusSummary(report, avFallback);
  const ai = analysis === undefined ? null : aiSummary(analysis);

  return (
    <Card title="What was checked" id="result-layers">
      <div className="layers">
        <section className="layer" aria-labelledby="layer-local">
          <h3 id="layer-local" className="layer__title">Local scan <span className="muted">decides the verdict</span></h3>
          <StatusPill status={VERDICT_TO_STATUS[report.verdict] ?? 'incomplete'} />
          <ul className="layer__facts">
            <li className={coverage.full ? undefined : 'is-risk'}>{coverage.text}</li>
            <li className={av.tone === 'neutral' ? undefined : 'is-risk'}>{av.text}</li>
            <li className={gaps.length ? 'is-risk' : undefined}>
              {gaps.length
                ? `Not run: ${gaps.map((g) => `${g.name} (${g.state})`).join('; ')}`
                : coverage.full
                  ? 'Every local detector ran.'
                  : 'Every local detector ran, but only on the inspected rows.'}
            </li>
          </ul>
        </section>

        <section className="layer" aria-labelledby="layer-ti">
          <h3 id="layer-ti" className="layer__title">Threat intelligence <span className="muted">extra evidence only</span></h3>
          <ToneChip tone={ti.tone}>{ti.word}</ToneChip>
          <p className="layer__text">{ti.text}</p>
          <ul className="layer__providers">
            {providers.map((p) => (
              <li key={p.id}>
                <strong>{p.name}</strong>
                <span className={`layer__state layer__state--${p.tone}`}>{p.text}</span>
              </li>
            ))}
          </ul>
        </section>

        <section className="layer" aria-labelledby="layer-ai">
          <h3 id="layer-ai" className="layer__title">AI analysis <span className="muted">advisory only</span></h3>
          {ai ? (
            <>
              <ToneChip tone={ai.tone}>{ai.word}</ToneChip>
              <p className="layer__text">{ai.text}</p>
            </>
          ) : (
            <p className="layer__text muted">Checking whether an analysis exists.</p>
          )}
        </section>
      </div>
    </Card>
  );
}
