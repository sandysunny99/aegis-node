# Dependencies added for detection work

Every runtime dependency added from Phase A.5 onwards gets an entry here: name, pinned version, licence, maintainer, last release date, reason, and the source of those facts. Anything AGPL/GPL, unmaintained for 12+ months, or over 50 MB needs the owner's approval first.

| Name | Pinned version | Licence | Maintainer | Last release | Reason | Checked |
|---|---|---|---|---|---|---|
| pefile | 2024.8.26 | MIT | Ero Carrera | 2024-08-26 | HEUR-003 PE import heuristic in `scanner/heuristics.py` was silently skipped because pefile was never installed (Phase A gap #16) | https://pypi.org/pypi/pefile/json, 15 Oct 2026 |

## Notes

- **pefile is past the 12-month rule.** Its last release is 26 months old. It was added because the owner's Phase A.5 decision named it explicitly. It is a pure-Python parser with no network access, used only on files that contain a PE header. If a maintained alternative is preferred, the PE checks can move to the planned capa / LIEF layer in Phase C.
- `libmagic1` (system package, BSD-2-Clause) was already in the backend `Dockerfile`; no change was needed there. On Windows without a libmagic DLL, scans now carry `DETECTOR_UNAVAILABLE:libmagic` instead of skipping HEUR-007 silently.

## Oracle scan VM (deploy/oracle-clamav, not part of the Render image)

| Name | Pinned | Licence | Reason | Checked |
|---|---|---|---|---|
| clamav/clamav-debian | 1.5.4 | GPL-2.0 (ClamAV) | Real ClamAV engine with arm64 images; runs as a separate service, not linked into Aegis | Docker Hub manifest, 15 Oct 2026 |
| benzino77/clamav-rest-api | 1.6.15 | MIT | REST wrapper Aegis already uses (`FILES` field) | Docker Hub manifest, 15 Oct 2026 |
| caddy | 2.10.2 | Apache-2.0 | HTTPS with automatic certificates | Docker Hub manifest, 15 Oct 2026 |
| python | 3.12-slim | PSF | Gateway base image | Docker Hub manifest, 17 Oct 2026 |
| fastapi / uvicorn / httpx / python-multipart | 0.143.0 / 0.54.0 / 0.28.1 / 0.0.32 | MIT / BSD-3 / BSD-3 / Apache-2.0 | Scan gateway; same versions as the tested backend venv | local venv, 17 Oct 2026 |

ClamAV is GPL-2.0. It runs as its own container and Aegis only calls it over HTTP; it is not linked into Aegis. It was already part of the project before this change. clamav-rest-api's MIT licence was checked on https://github.com/benzino77/clamav-rest-api (17 Oct 2026).
