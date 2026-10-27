/**
 * The three result layers the UI reports separately (brief Phase J / H):
 *   1. local scan      : the deterministic verdict, coverage and detector gaps
 *   2. threat intel    : optional enrichment, per provider, never the verdict
 *   3. AI analysis     : advisory interpretation, never the verdict
 * Everything here is derived from fields the API returns; nothing is assumed.
 */

// Display text for providers the UI knows. The list itself comes from GET /health/detectors
// (layer L4) when the server has it; older servers fall back to the original three.
const PROVIDER_TEXT = {
  virustotal: { name: 'VirusTotal', sends: 'file SHA-256', idle: 'No result recorded for the file hash.' },
  urlhaus: { name: 'URLhaus', sends: 'URLs found in the file', idle: 'No URLs were found in the file, so nothing was looked up.' },
  abuseipdb: { name: 'AbuseIPDB', sends: 'public IPs found in the file', idle: 'No public IP addresses were found in the file, so nothing was looked up.' },
  malwarebazaar: { name: 'MalwareBazaar', sends: 'file SHA-256', idle: 'No result recorded for the file hash.' },
  threatfox: { name: 'ThreatFox', sends: 'file SHA-256 and URLs found in the file', idle: 'No result recorded for the file hash or URLs.' },
  circl_hashlookup: { name: 'CIRCL hashlookup', sends: 'file SHA-256', idle: 'No result recorded for the file hash.' },
  yaraify: { name: 'YARAify', sends: 'file SHA-256', idle: 'No result recorded for the file hash.' },
  hybrid_analysis: { name: 'Hybrid Analysis', sends: 'file SHA-256', idle: 'No result recorded for the file hash.' },
  urlscan: { name: 'urlscan.io', sends: 'URLs found in the file (search only)', idle: 'No URLs were found in the file, so nothing was looked up.' },
};
const LEGACY_PROVIDERS = ['virustotal', 'urlhaus', 'abuseipdb'];

/** Provider rows: the server catalogue (or the legacy three) plus any provider named in the report. */
export function providerList(tiReport, catalog) {
  const fromCatalog = catalog?.filter((d) => d.layer === 'L4');
  const rows = fromCatalog ? fromCatalog.map((d) => ({ id: d.name, lookup: d.lookup })) : LEGACY_PROVIDERS.map((id) => ({ id }));
  const named = [...(tiReport?.providers_checked ?? []), ...(tiReport?.evidence ?? []).map((e) => e.provider)];
  for (const id of named) if (id && !rows.some((r) => r.id === id)) rows.push({ id });
  return rows.map(({ id, lookup }) => ({
    id,
    name: PROVIDER_TEXT[id]?.name ?? id,
    sends: PROVIDER_TEXT[id]?.sends ?? lookup ?? 'indicators found in the file',
    idle: PROVIDER_TEXT[id]?.idle ?? 'No indicator in the file was looked up.',
  }));
}

const ANSWERED = new Set(['MATCH', 'NO_MATCH']);

/**
 * Per-lookup result state. Newer APIs send `result_state` (MATCH, NO_MATCH, TIMEOUT,
 * RATE_LIMITED, UNAUTHORIZED, UNAVAILABLE, INVALID_RESPONSE, NOT_QUERIED); reports stored
 * before that field existed are derived from `error_status` and `reputation`.
 */
export function lookupState(e) {
  if (e.result_state) return e.result_state;
  if (e.error_status) return String(e.error_status).toUpperCase();
  return e.reputation === 'malicious' || e.reputation === 'suspicious' ? 'MATCH' : 'NO_MATCH';
}

/**
 * Per-provider state from a TIFusionReport.
 * state: match | known | no_match | unavailable | not_queried | disabled | not_run
 * `catalog` is GET /health/detectors `detectors` (null on servers without it).
 * tone:  breach | risk | clean | neutral (for the status chip colour)
 */
export function providerStates(tiReport, catalog = null) {
  return providerList(tiReport, catalog).map((p) => {
    if (!tiReport) {
      return { ...p, state: 'not_run', tone: 'risk', text: 'Enrichment did not complete for this scan.' };
    }
    if (tiReport.status === 'disabled' || !(tiReport.providers_checked ?? []).includes(p.id)) {
      return { ...p, state: 'disabled', tone: 'neutral', text: 'Not configured on this server, so not queried.' };
    }
    const evidence = (tiReport.evidence ?? []).filter((e) => e.provider === p.id && lookupState(e) !== 'NOT_QUERIED');
    if (evidence.length === 0) {
      return { ...p, state: 'not_queried', tone: 'neutral', text: p.idle };
    }
    const failed = evidence.filter((e) => !ANSWERED.has(lookupState(e)));
    const answered = evidence.filter((e) => ANSWERED.has(lookupState(e)));
    // CIRCL's "known_good" is an annotation that fusion ignores: never a hit, never a verdict.
    const known = answered.filter((e) => e.reputation === 'known_good');
    const hits = answered.filter((e) => lookupState(e) === 'MATCH' && e.reputation !== 'known_good');
    if (hits.length > 0) {
      const worst = hits.some((e) => e.reputation === 'malicious') ? 'malicious' : 'suspicious';
      return { ...p, state: 'match', tone: 'breach', text: `Match: ${hits.length} of ${evidence.length} indicator${evidence.length === 1 ? '' : 's'} reported ${worst}.`, evidence };
    }
    if (known.length > 0) {
      return { ...p, state: 'known', tone: 'neutral', text: `Known file (annotation): the hash is listed as known software. This is not a verdict and does not show the data is safe.`, evidence };
    }
    if (answered.length === 0) {
      const reasons = [...new Set(failed.map((e) => (e.error_status || lookupState(e)).toLowerCase().replace(/_/g, ' ')))].join(', ');
      return { ...p, state: 'unavailable', tone: 'risk', text: `Unavailable (${reasons}), so this provider gave no evidence.`, evidence };
    }
    const partial = failed.length > 0 ? ` ${failed.length} lookup${failed.length === 1 ? '' : 's'} failed.` : '';
    return {
      ...p,
      state: failed.length > 0 ? 'unavailable' : 'no_match',
      tone: failed.length > 0 ? 'risk' : 'neutral',
      text: `No malicious match for ${answered.length} indicator${answered.length === 1 ? '' : 's'}.${partial} A no-match is not proof the data is safe.`,
      evidence,
    };
  });
}

/** One-line state for the whole enrichment layer. */
export function enrichmentSummary(tiReport) {
  if (!tiReport) return { word: 'Not completed', tone: 'risk', text: 'Threat-intelligence enrichment failed or did not run for this scan.' };
  // Newer APIs send enrichment_status; older stored reports only have `status`.
  switch (tiReport.enrichment_status) {
    case 'DISABLED': return { word: 'Off', tone: 'neutral', text: 'No threat-intelligence provider is configured, so nothing was sent to a third party.' };
    case 'COMPLETE': return { word: 'Completed', tone: 'neutral', text: 'Every lookup answered (match or no match).' };
    case 'PARTIAL': return { word: 'Partial', tone: 'risk', text: 'Some lookups failed; the evidence below is incomplete.' };
    case 'UNAVAILABLE': return { word: 'Unavailable', tone: 'risk', text: 'Every lookup failed; there is no enrichment evidence.' };
    default: break;
  }
  switch (tiReport.status) {
    case 'disabled': return { word: 'Off', tone: 'neutral', text: 'No threat-intelligence provider is configured, so nothing was sent to a third party.' };
    case 'active': return { word: 'Completed', tone: 'neutral', text: 'Every configured provider answered.' };
    case 'degraded': return { word: 'Partial', tone: 'risk', text: 'Some provider lookups failed; the evidence below is incomplete.' };
    case 'error': return { word: 'Failed', tone: 'risk', text: 'Every configured provider lookup failed; there is no enrichment evidence.' };
    default: return { word: tiReport.status, tone: 'neutral', text: '' };
  }
}

/** One-line state for the AI layer. `analysis` is null when none has run (API 404). */
export function aiSummary(analysis) {
  if (!analysis) return { word: 'Not run', tone: 'neutral', text: 'No AI analysis has been requested for this dataset.' };
  if (analysis.guardrail_status === 'BLOCK') {
    return { word: 'Blocked', tone: 'risk', text: 'The prompt-injection guardrail blocked the evidence, so no model was called.' };
  }
  if (analysis.status === 'completed') {
    return { word: 'Completed', tone: 'neutral', text: `Explained by ${analysis.final_provider || analysis.model_name}. Advisory only; it cannot change the verdict.` };
  }
  if (analysis.status === 'unavailable') return { word: 'Unavailable', tone: 'risk', text: 'No AI provider answered. The verdict does not depend on it.' };
  return { word: 'Failed', tone: 'risk', text: analysis.error || 'The AI analysis failed. The verdict does not depend on it.' };
}

const AV_NAMES = { clamav: 'ClamAV', clamav_rest: 'ClamAV', metadefender: 'MetaDefender (hash lookup)' };
const AV_REASONS = {
  METADEFENDER_HASH_NOT_FOUND: 'no record of this file, so no signature result',
  RATE_LIMITED: 'rate limited, so no signature result',
  AUTH: 'API key rejected, so no signature result',
  UNREACHABLE: 'unreachable, so no signature result',
};

/**
 * Antivirus line for the local layer, named after the provider that actually ran.
 * A MetaDefender "clean" covers the whole file by hash; it says nothing about rows
 * the content scanner did not inspect.
 */
export function antivirusSummary(report, avProviderFallback = null) {
  if (!report) return null;
  const provider = report.av_provider || avProviderFallback;
  const name = AV_NAMES[provider] ?? (provider ? provider : 'Antivirus');
  const status = report.clamav_status;
  if (status === 'infected') return { tone: 'breach', text: `Antivirus, ${name}: infected${report.clamav_virus_name ? ` (${report.clamav_virus_name})` : ''}.` };
  if (status === 'clean') {
    const scope = provider === 'metadefender' ? ' (known-clean hash)' : '';
    return { tone: 'neutral', text: `Antivirus, ${name}: clean${scope}.` };
  }
  const why = AV_REASONS[report.av_reason] ?? 'no result for this file';
  return { tone: 'risk', text: `Antivirus, ${name}: ${why}.` };
}

/** Coverage line for the local layer. */
export function coverageSummary(report) {
  if (!report) return null;
  const full = report.coverage_status === 'FULL';
  const rows = report.rows_total != null ? `${report.rows_inspected} of ${report.rows_total} rows` : `${report.rows_inspected} rows`;
  return {
    full,
    tone: full ? 'neutral' : 'risk',
    text: full
      ? `Full coverage (${rows} inspected).`
      : `${report.coverage_status === 'PARTIAL' ? 'Partial' : report.coverage_status} coverage: ${report.coverage_percentage}% inspected (${rows}). Content beyond that was not checked.`,
  };
}
