/**
 * Scan history helpers (contract: docs/SCAN_HISTORY_API.md on the detection branch).
 * Pure functions so the wording and the "API absent" rule are unit-tested.
 */
import { enrichmentSummary } from './layers.js';
import { VERDICT_TO_STATUS, statusToPlate } from './statusToPlate.js';

// Filter values the API accepts (GET /api/v1/scans).
export const VERDICTS = ['clean_verified', 'clean_with_limitations', 'suspicious', 'malicious', 'scan_incomplete'];
export const DATASET_STATUS_FILTERS = ['clean', 'clean_limited', 'incomplete', 'quarantined', 'suspicious', 'remediated', 'partial_remediated', 'remediated_unverified', 'error'];
export const FILE_FORMATS = ['csv', 'json', 'jsonl', 'parquet', 'xlsx', 'txt'];
export const ENRICHMENT_STATUSES = ['COMPLETE', 'PARTIAL', 'UNAVAILABLE', 'DISABLED'];
export const TARGETS = [
  { value: 'original', label: 'Uploaded files' },
  { value: 'sanitized', label: 'Verification re-scans' },
  { value: 'all', label: 'Both' },
];

const FILTER_KEYS = ['verdict', 'dataset_status', 'file_format', 'enrichment_status', 'target'];

/** Local-midnight ISO time for a YYYY-MM-DD date input, `days` later. */
function dayStart(date, days = 0) {
  const d = new Date(`${date}T00:00:00`);
  d.setDate(d.getDate() + days);
  return d.toISOString();
}

/** Query string for GET /scans. `from` / `to` are inclusive days; the API's `until` is exclusive. */
export function scanQuery(filters = {}, page = 1, pageSize = 20) {
  const q = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
  for (const key of FILTER_KEYS) {
    const v = filters[key];
    if (v && (v !== 'all' || key === 'target')) q.set(key, v);
  }
  if (filters.from) q.set('since', dayStart(filters.from));
  if (filters.to) q.set('until', dayStart(filters.to, 1));
  return q;
}

/**
 * True when the server does not have the history routes at all (an older backend):
 * unknown routes answer a bare 404 "Not Found", while the history routes say
 * "Resource not found." for a missing scan or dataset.
 */
export function historyMissing(err) {
  return err?.status === 404 && /^not found$/i.test(String(err.detail ?? '').trim());
}

/** Warning text when history will not survive a restart; null when durable or unknown. */
export function persistenceNote(persistence) {
  if (!persistence || persistence.durable) return null;
  return 'This server keeps history on temporary storage, so it will be lost when the server restarts.';
}

export function notRecorded(value) {
  return value ?? 'Not recorded';
}

export function verdictStatus(verdict) {
  return VERDICT_TO_STATUS[verdict] ?? 'incomplete';
}

export function verdictLabel(verdict) {
  return VERDICT_TO_STATUS[verdict] ? statusToPlate(VERDICT_TO_STATUS[verdict]).label : String(verdict ?? 'unknown verdict');
}

export function enrichmentLabel(status) {
  return enrichmentSummary({ enrichment_status: status }).word ?? status;
}

const AV_NAMES = { clamav: 'ClamAV', clamav_rest: 'ClamAV', metadefender: 'MetaDefender' };
const AV_REASONS = {
  METADEFENDER_HASH_NOT_FOUND: 'no record of this file',
  RATE_LIMITED: 'rate limited',
  AUTH: 'key rejected',
  UNREACHABLE: 'unreachable',
};
const DETECTORS = { clamav: 'Antivirus (ClamAV)', yara: 'YARA rules', heuristics: 'Heuristic checks', content_rules: 'Content rules' };
const DETECTOR_STATES = { ran: 'ran', unavailable: 'unavailable', disabled: 'switched off', incomplete: 'incomplete' };
const PROVIDERS = { virustotal: 'VirusTotal', urlhaus: 'URLhaus', abuseipdb: 'AbuseIPDB' };

const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;
const words = (code) => String(code).toLowerCase().replace(/_/g, ' ');
const sentence = (code) => { const w = words(code); return w.charAt(0).toUpperCase() + w.slice(1); };

/**
 * Title, text and tone for one ScanEvent. tone: breach (failed), risk (ran with a gap),
 * neutral (ran). The timeline only holds steps that actually ran.
 */
export function describeEvent(event) {
  const d = event.detail ?? {};
  const failed = event.outcome === 'failed';
  const base = { tone: failed ? 'breach' : 'neutral', text: '' };
  switch (event.event_type) {
    case 'UPLOAD_ACCEPTED':
      return { ...base, title: 'Upload accepted', text: d.file_format ? `${String(d.file_format).toUpperCase()} file stored` : '' };
    case 'SCAN_STARTED':
      return { ...base, title: 'Scan started', text: `Profile: ${notRecorded(d.profile)}. Antivirus: ${notRecorded(d.av_provider)}.` };
    case 'DETECTOR_COMPLETED': {
      const isAv = d.detector === 'clamav';
      const state = (isAv && d.state !== 'ran' && AV_REASONS[d.reason]) || DETECTOR_STATES[d.state] || words(d.state ?? 'unknown');
      const name = isAv && d.provider ? `Antivirus (${AV_NAMES[d.provider] ?? d.provider})` : (DETECTORS[d.detector] ?? d.detector);
      return {
        ...base,
        title: `${name}: ${state}`,
        tone: failed ? 'breach' : d.state === 'ran' ? 'neutral' : 'risk',
      };
    }
    case 'THREAT_INTEL_LOOKUP_COMPLETED':
    case 'THREAT_INTEL_LOOKUP_FAILED': {
      const states = Object.entries(d.result_states ?? {}).map(([s, n]) => `${n} ${words(s)}`).join(', ');
      const lookups = d.lookups != null ? plural(d.lookups, 'lookup') : '';
      return {
        ...base,
        tone: failed ? 'breach' : 'neutral',
        title: `${PROVIDERS[d.provider] ?? d.provider} lookup ${failed ? 'failed' : 'completed'}`,
        text: [lookups, states].filter(Boolean).join(': '),
      };
    }
    case 'SCAN_COMPLETED': {
      const parts = [
        verdictLabel(d.verdict),
        d.coverage_status && `coverage ${words(d.coverage_status)}`,
        d.enrichment_status && `threat intelligence ${enrichmentLabel(d.enrichment_status).toLowerCase()}`,
        d.limitations?.length ? plural(d.limitations.length, 'limitation') : null,
        d.duration_ms != null ? `${d.duration_ms} ms` : null,
      ].filter(Boolean);
      return { ...base, title: 'Scan completed', text: parts.join(', ') };
    }
    case 'SCAN_FAILED':
      return { ...base, tone: 'breach', title: 'Scan failed', text: d.error ? `Error: ${d.error}` : '' };
    case 'AI_ANALYSIS_STARTED':
      return { ...base, title: 'AI analysis started', text: d.llm_mode ? `Mode: ${d.llm_mode}` : '' };
    case 'AI_ANALYSIS_COMPLETED':
      return {
        ...base,
        title: `AI analysis ${words(d.status ?? (failed ? 'failed' : 'completed'))}`,
        text: d.guardrail_status === 'BLOCK'
          ? 'The prompt-injection guardrail blocked the evidence, so no model was called.'
          : d.provider ? `Provider: ${d.provider}${d.fallback_used ? ' (fallback)' : ''}. Advisory only.` : '',
      };
    case 'REMEDIATION_STARTED':
      return { ...base, title: 'Remediation started', text: d.original_findings != null ? `${plural(d.original_findings, 'finding')} to address` : '' };
    case 'VERIFICATION_SCAN_COMPLETED':
      return { ...base, title: 'Sanitized copy re-scanned', text: verdictLabel(d.verdict) };
    case 'REMEDIATION_COMPLETED':
      return {
        ...base,
        tone: failed ? 'breach' : d.remediation_status === 'completed' ? 'neutral' : 'risk',
        title: `Remediation ${words(d.remediation_status ?? 'completed')}`,
        text: [d.changes != null && plural(d.changes, 'change'), d.remaining_actionable != null && `${d.remaining_actionable} actionable left`].filter(Boolean).join(', '),
      };
    case 'REMEDIATION_FAILED':
      return { ...base, tone: 'breach', title: 'Remediation failed', text: d.stage ? `Stage: ${d.stage}` : '' };
    default:
      return { ...base, title: sentence(event.event_type) };
  }
}
