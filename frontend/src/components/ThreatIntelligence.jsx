import { enrichmentSummary, providerStates } from '../status/layers';
import Card from '../ui/Card';
import Table from '../ui/Table';
import ToneChip from '../ui/ToneChip';

const REPUTATION_TEXT = {
  malicious: 'Malicious',
  suspicious: 'Suspicious',
  benign: 'No malicious match',
  unknown: 'Unknown (no match)',
};

/**
 * Threat-intelligence evidence, rendered only from TIFusionReport fields. Each provider's
 * state is shown truthfully: match, no match, unavailable, not queried or not configured.
 */
export default function ThreatIntelligence({ tiReport }) {
  const summary = enrichmentSummary(tiReport);
  const providers = providerStates(tiReport);
  const evidence = tiReport?.evidence ?? [];

  return (
    <Card title="Threat intelligence" id="threat-intel" actions={<ToneChip tone={summary.tone}>{summary.word}</ToneChip>}>
      <p className="card-sub card-lede">
        Optional enrichment from third-party lookups. It never changes the local verdict. {summary.text}
      </p>
      <ul className="provider-list">
        {providers.map((p) => (
          <li key={p.id}>
            <div>
              <strong>{p.name}</strong>
              <span className="muted"> receives the {p.sends}</span>
            </div>
            <span className={`layer__state layer__state--${p.tone}`}>{p.text}</span>
          </li>
        ))}
      </ul>
      {tiReport?.conflicts?.length > 0 && (
        <p className="notice notice--risk">Providers disagree: {tiReport.conflicts.join(', ')}</p>
      )}
      {evidence.length > 0 && (
        <Table
          caption="Threat intelligence evidence"
          rowKey={(e) => `${e.provider}-${e.indicator}`}
          columns={[
            { key: 'provider', header: 'Provider', render: (e) => providers.find((p) => p.id === e.provider)?.name ?? e.provider },
            { key: 'indicator_type', header: 'Type' },
            { key: 'indicator', header: 'Indicator', mono: true, render: (e) => <span className="break">{e.indicator}</span> },
            { key: 'reputation', header: 'Result', render: (e) => (e.error_status ? `Unavailable (${e.error_status})` : REPUTATION_TEXT[e.reputation] ?? e.reputation) },
          ]}
          rows={evidence}
        />
      )}
    </Card>
  );
}
