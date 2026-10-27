/**
 * Plain-language text for verification_limitations codes from the scan engine.
 * Unknown codes are shown verbatim so nothing the backend reports is hidden.
 */
const DETECTOR_NAMES = {
  yara: 'YARA rules',
  libmagic: 'File-type detection (libmagic)',
  pefile: 'PE import analysis (pefile)',
  heuristics: 'Heuristic checks',
  encoding_normalization: 'Encoding normalisation',
};

export function describeLimitation(code) {
  const [kind, detail] = String(code).split(':');
  if (kind === 'DETECTOR_UNAVAILABLE') {
    return `${DETECTOR_NAMES[detail] ?? detail} could not run on this server, so it did not check this file.`;
  }
  if (kind === 'DETECTOR_DISABLED') {
    return `${DETECTOR_NAMES[detail] ?? detail} is switched off in the server configuration.`;
  }
  if (code === 'VT_UNAVAILABLE_AUTH') return 'VirusTotal rejected the API key, so no hash reputation was checked.';
  if (String(code).startsWith('VT_UNAVAILABLE_')) return `VirusTotal was unavailable (${detail ?? code.slice(15).toLowerCase()}).`;
  if (kind === 'INSPECTION_LIMIT') {
    // e.g. INSPECTION_LIMIT:xlsx_rows=10000
    const [what, value] = String(detail ?? '').split('=');
    const label = { xlsx_rows: 'workbook rows', xlsx_count: 'workbook rows counted' }[what] ?? what;
    return `The scanner stopped at its limit of ${value ?? '?'} ${label}, so content beyond it was not inspected.`;
  }
  if (code === 'AV_SIGNATURE_SCAN_OFF') return 'This deployment runs without a signature antivirus engine (by configuration). The file hash was checked with MetaDefender and the threat-intelligence providers instead, which only know files they have seen before.';
  if (code === 'CLAMAV_UNAVAILABLE') return 'No antivirus signature result for this file (MetaDefender only knows files it has seen before; a ClamAV engine may be unreachable).';
  if (code === 'PARTIAL_DATASET_SCAN') return 'Only part of the dataset was inspected, so findings may be incomplete.';
  if (code === 'PARSER_LIMITATION') return 'The file could not be fully parsed, so some values were not checked cell by cell.';
  if (code === 'MALWARE_REFERENCE_ONLY') return 'The data mentions malware names (for example in research notes) but contains no malware artifact.';
  if (code === 'CONFLICT_TI_MALICIOUS') return 'Threat intelligence marks an indicator in this file as malicious although the local scan found it clean.';
  if (code === 'TI_EVIDENCE_DISAGREEMENT') return 'Threat-intelligence providers disagree about this file.';
  if (code === 'CONFLICT_VT_MALICIOUS') return 'VirusTotal reports this file hash as malicious although the local scan found it clean.';
  if (String(code).includes('_UNAVAILABLE_')) {
    const [provider, , ...rest] = String(code).split('_');
    return `${provider.charAt(0)}${provider.slice(1).toLowerCase()} was unavailable (${rest.join(' ').toLowerCase()}).`;
  }
  if (code === 'THREAT_INTEL_FAILURE' || code === 'THREAT_INTEL_FUSION_FAILURE') return 'External threat-intelligence enrichment failed for this scan.';
  return code;
}

/** Detectors named as unavailable or disabled, for the "what ran" summary. */
export function detectorGaps(limitations = []) {
  return limitations
    .map((code) => String(code).split(':'))
    .filter(([kind]) => kind === 'DETECTOR_UNAVAILABLE' || kind === 'DETECTOR_DISABLED')
    .map(([kind, detail]) => ({
      name: DETECTOR_NAMES[detail] ?? detail,
      state: kind === 'DETECTOR_DISABLED' ? 'switched off' : 'unavailable',
    }));
}
