import Card from '../ui/Card';
import Table from '../ui/Table';

const PROVIDER_NAMES = { virustotal: 'VirusTotal', urlhaus: 'URLhaus', abuseipdb: 'AbuseIPDB' };
const STRENGTH_TEXT = {
  NONE: 'No provider returned evidence.',
  SINGLE_PROVIDER: 'One provider returned evidence.',
  CORROBORATED: 'More than one provider agrees.',
  CONFLICTED: 'Providers disagree with each other.',
  PROVIDER_UNAVAILABLE: 'Configured providers were unavailable.',
};

/**
 * Threat intelligence, rendered only from the fields the API returns (TIFusionReport):
 * status, evidence[], evidence_strength, providers_checked, limitations, conflicts.
 */
export default function ThreatIntelligence({ tiReport }) {
  if (!tiReport) return null;

  if (tiReport.status === 'disabled') {
    return (
      <Card title="Threat intelligence" id="threat-intel">
        <p className="muted">
          No external provider is configured, so no hashes, URLs or IP addresses were sent anywhere.
          VirusTotal, URLhaus and AbuseIPDB are opt-in on the server.
        </p>
      </Card>
    );
  }

  const evidence = tiReport.evidence ?? [];
  const checked = (tiReport.providers_checked ?? []).map((p) => PROVIDER_NAMES[p] ?? p).join(', ') || 'none';

  return (
    <Card title="Threat intelligence" id="threat-intel">
      <p className="card-sub card-lede">External enrichment. It never overrides the local verdict.</p>
      <dl className="kv kv--spaced">
        <dt>Providers checked</dt><dd>{checked}</dd>
        <dt>Evidence strength</dt><dd>{STRENGTH_TEXT[tiReport.evidence_strength] ?? tiReport.evidence_strength}</dd>
        {tiReport.conflicts?.length > 0 && (<><dt>Conflicts</dt><dd>{tiReport.conflicts.join(', ')}</dd></>)}
      </dl>
      {evidence.length === 0 ? (
        <p className="empty">The configured providers returned no indicators for this dataset.</p>
      ) : (
        <Table
          caption="Threat intelligence evidence"
          rowKey={(e) => `${e.provider}-${e.indicator}`}
          columns={[
            { key: 'provider', header: 'Provider', render: (e) => PROVIDER_NAMES[e.provider] ?? e.provider },
            { key: 'indicator_type', header: 'Type' },
            { key: 'indicator', header: 'Indicator', mono: true, render: (e) => <span className="break">{e.indicator}</span> },
            { key: 'reputation', header: 'Reputation', render: (e) => (e.error_status ? `unavailable (${e.error_status})` : e.reputation) },
          ]}
          rows={evidence}
        />
      )}
    </Card>
  );
}
