# Phase A (pipeline verification) records

These three files were written at `c895a6b` (tag `core-freeze-2026-10-13`) before the merge. Line numbers in them refer to that commit, not to this branch.

- `PHASE_A_REPORT.md`: commands, test counts and the local end-to-end run.
- `PIPELINE_MAP.md`: every stage from upload to verdict, mapped from the code.
- `INTEGRATION_GAPS.md`: 24 numbered gaps.

## Gap status on `integrate/core-audit` (core-baseline-v2)

| Gap | Status | Commit |
|---|---|---|
| #1 limited / incomplete scans stored as `clean` | Fixed: `clean_limited`, `incomplete` | `fix(core): store clean only for clean_verified scans` |
| #2 refused re-scan flips status to `error` | Fixed on the audit branch (C1), kept through the merge | `d6e43e1` |
| #3 remediation `completed` without a verified re-scan | Fixed: `unverified` / `remediated_unverified`, re-scan stored | `fix(core): remediation is completed only when the re-scan verifies it` |
| #4 trailing blank line makes CSV partial | Fixed | `fix(core): count CSV rows with the parser that inspects them` |
| #9 VirusTotal stored as a finding | Fixed: TI evidence, `VT_UNAVAILABLE_AUTH` | `fix(ti): VirusTotal is threat-intel evidence...` |
| #14 TI defaults on | Fixed on the audit branch (`8e5bdde`) | merge |
| #15 TI reports unconfigured providers as checked | Fixed | same commit as #9 |
| #16 detectors that fail to load are silent | Fixed: `DETECTOR_UNAVAILABLE:<name>`, pefile added | `fix(core): a detector that fails to load blocks clean_verified` |
| #17 MetaDefender uploads whole files | Fixed: hash lookup only | `fix(av): MetaDefender looks up the SHA-256 only...` |
| #18 dead detector flags | Fixed: read through settings, `DETECTOR_DISABLED:<name>` | `fix(core): detector flags come from settings...` |
| #20 indicator selection non-deterministic | Fixed on the audit branch (`d6e43e1`) | merge |
| #23 provider list not rate limited | Fixed on the audit branch (S7) | merge |
| #5–#8, #10–#13 UI gaps | Open: Bastion P0 on `feat/bastion-frontend`, using the new status values | — |
| #19, #21, #22, #24 | Open | — |
