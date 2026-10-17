/**
 * The single source of truth for how a dataset status looks. The shield, the status
 * pill and the datasets table all read this map, so they cannot disagree.
 *
 * plate: the shield material (see DESIGN.md)
 * tone:  which --status-* token colours the word and icon
 * icon:  lucide-react icon name
 * urgency: default table sort, lower = more urgent
 */
export const STATUS_TO_PLATE = Object.freeze({
  quarantined: { plate: 'breached', label: 'Quarantined', tone: 'breach', icon: 'ShieldX', urgency: 0 },
  suspicious: { plate: 'degraded', label: 'Suspicious', tone: 'risk', icon: 'ShieldAlert', urgency: 1 },
  partial_remediated: { plate: 'degraded', label: 'Partly remediated', tone: 'risk', icon: 'ShieldHalf', urgency: 2 },
  remediated_unverified: { plate: 'degraded', label: 'Remediation unverified', tone: 'risk', icon: 'ShieldQuestion', urgency: 3 },
  error: { plate: 'degraded', label: 'Scan failed', tone: 'breach', icon: 'CircleAlert', urgency: 4 },
  incomplete: { plate: 'degraded', label: 'Scan incomplete', tone: 'risk', icon: 'CircleDashed', urgency: 5 },
  clean_limited: { plate: 'degraded', label: 'Clean, limited scan', tone: 'risk', icon: 'ShieldMinus', urgency: 6 },
  scanning: { plate: 'scanning', label: 'Scanning', tone: 'scanning', icon: 'LoaderCircle', urgency: 7 },
  uploaded: { plate: 'unscanned', label: 'Not scanned', tone: 'neutral', icon: 'Circle', urgency: 8 },
  remediated: { plate: 'healthy', label: 'Remediated', tone: 'clean', icon: 'ShieldCheck', urgency: 9 },
  clean: { plate: 'healthy', label: 'Clean', tone: 'clean', icon: 'ShieldCheck', urgency: 10 },
});

export const DATASET_STATUSES = Object.freeze(Object.keys(STATUS_TO_PLATE));

/** Scan verdicts (ScanReportRecord.verdict) mapped onto the dataset status vocabulary. */
export const VERDICT_TO_STATUS = Object.freeze({
  clean_verified: 'clean',
  clean_with_limitations: 'clean_limited',
  scan_incomplete: 'incomplete',
  suspicious: 'suspicious',
  malicious: 'quarantined',
});

const isDev = typeof import.meta !== 'undefined' && import.meta.env ? import.meta.env.DEV : true;

/**
 * Look up a dataset status. An unknown status fails loudly in development (so a new
 * backend status cannot slip through) and degrades to a neutral "Unknown status"
 * in production rather than pretending the dataset is clean.
 */
export function statusToPlate(status) {
  const entry = STATUS_TO_PLATE[status];
  if (entry) return entry;
  if (isDev) {
    throw new Error(`Unknown dataset status "${status}". Add it to src/status/statusToPlate.js.`);
  }
  return { plate: 'unscanned', label: 'Unknown status', tone: 'neutral', icon: 'CircleHelp', urgency: 99 };
}

/** The status to display: the latest report verdict wins over a legacy "clean" row. */
export function effectiveStatus(datasetStatus, verdict) {
  if (datasetStatus === 'clean' && verdict && VERDICT_TO_STATUS[verdict]) {
    return VERDICT_TO_STATUS[verdict];
  }
  return datasetStatus;
}

export function byUrgency(a, b) {
  return statusToPlate(a).urgency - statusToPlate(b).urgency;
}
