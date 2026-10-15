# Dependencies added for detection work

Every runtime dependency added from Phase A.5 onwards gets an entry here: name, pinned version, licence, maintainer, last release date, reason, and the source of those facts. Anything AGPL/GPL, unmaintained for 12+ months, or over 50 MB needs the owner's approval first.

| Name | Pinned version | Licence | Maintainer | Last release | Reason | Checked |
|---|---|---|---|---|---|---|
| pefile | 2024.8.26 | MIT | Ero Carrera | 2024-08-26 | HEUR-003 PE import heuristic in `scanner/heuristics.py` was silently skipped because pefile was never installed (Phase A gap #16) | https://pypi.org/pypi/pefile/json, 15 Oct 2026 |

## Notes

- **pefile is past the 12-month rule.** Its last release is 26 months old. It was added because the owner's Phase A.5 decision named it explicitly. It is a pure-Python parser with no network access, used only on files that contain a PE header. If a maintained alternative is preferred, the PE checks can move to the planned capa / LIEF layer in Phase C.
- `libmagic1` (system package, BSD-2-Clause) was already in the backend `Dockerfile`; no change was needed there. On Windows without a libmagic DLL, scans now carry `DETECTOR_UNAVAILABLE:libmagic` instead of skipping HEUR-007 silently.
