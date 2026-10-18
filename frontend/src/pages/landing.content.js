// Landing copy that describes the real scanner (scanner/, backend/services/). Nothing here
// claims a check the code does not run.

export const REPO_URL = 'https://github.com/sandysunny99/aegis-node';
export const DOC = (path) => `${REPO_URL}/blob/main/${path}`;

export const PROBLEMS = [
  {
    title: 'Datasets carry executable payloads',
    body: 'A CSV cell that starts with "=" runs as a formula in Excel. Exported files can also hide script tags, SQL fragments, shellcode or a whole embedded executable.',
  },
  {
    title: 'Text meant for models can carry instructions',
    body: 'Rows that end up in a RAG index or a training run can contain prompt-injection strings written to steer a model that later reads them.',
  },
  {
    title: 'Antivirus alone looks at the wrong layer',
    body: 'Signature scanners judge the file. Most dataset attacks live in individual cells, so the check has to read every value.',
  },
];

export const SCAN_STEPS = [
  { title: 'Receive and fingerprint', body: 'The upload streams to disk with a SHA-256 hash, a size limit, an extension allow-list and a magic-byte check that rejects PE, ELF and Mach-O binaries.' },
  { title: 'Antivirus', body: 'ClamAV scans the file locally, or MetaDefender is asked about the hash only. The file itself never leaves the server.' },
  { title: 'Heuristics and YARA', body: 'Entropy, packers, embedded executables, process-injection and downloader strings, base64 payloads and MIME mismatch, plus four YARA rules.' },
  { title: 'Every cell, every rule', body: 'Each value is decoded, normalised and checked against 22 content rules: formula and DDE injection, scripts, SQL, shellcode, C2 strings, macros and prompt injection.' },
  { title: 'Verdict, remediation, re-scan', body: 'The deterministic scanner decides the verdict. Remediation neutralises findings in a copy, and that copy is scanned again before it can be downloaded.' },
];

export const DETECTS = [
  { area: 'Formula injection', rules: 'FORM-001 to 003', what: 'Cells that start a spreadsheet formula, DDE command payloads, HYPERLINK to external URLs.' },
  { area: 'Script injection', rules: 'SCRP-001 to 003', what: '<script> tags, javascript: handlers and eval() or exec() calls inside values.' },
  { area: 'SQL injection', rules: 'SQLI-001, 002', what: 'Classic injection payloads and UNION SELECT patterns in text fields.' },
  { area: 'Prompt injection', rules: 'PROMPT-001, 002', what: 'Instruction-override text and jailbreak role-play directives aimed at a downstream model.' },
  { area: 'Malware artifacts', rules: 'MAL-001 to 011, BIN-001', what: 'EICAR, PE and ELF headers (raw or base64), PowerShell droppers, reverse shells, auto-run macros, IP:port C2 URLs, hex shellcode, null bytes.' },
  { area: 'Heuristics', rules: 'HEUR', what: 'High entropy, non-printable bytes, packers, embedded PE, MIME mismatch, base64 payloads, suspicious PE imports.' },
  { area: 'YARA', rules: '4 rules', what: 'EICAR, embedded PE dropper, shellcode NOP sled, web-shell dynamic eval.' },
  { area: 'Antivirus', rules: 'ClamAV / MetaDefender', what: 'Local signature scan, or a hash-only lookup when running on a host without ClamAV.' },
  { area: 'Threat intelligence (opt-in)', rules: 'VirusTotal, URLhaus, AbuseIPDB', what: 'Hash, URL and IP reputation as extra evidence. Off by default; never overrides the local verdict.' },
];

export const NOT_CHECKED = 'It does not check personal data, licences, or statistical poisoning of training labels.';
