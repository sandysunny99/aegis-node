# Sandboxing and analysis boundaries

Three different things, kept apart. Updated 18 Oct 2026.

## 1. Static analysis of uploads (what Aegis does on every upload)

Parsing runs **in the web process** (FastAPI worker threads). Uploads are only ever read: pandas, pyarrow, openpyxl (read-only, formulas read as text, never evaluated), `json`, YARA and byte scans. `tests/test_no_content_execution.py` fails the build if scanner or backend code calls `eval`/`exec`/`compile`/`__import__`, `os.system`/`os.popen`, `pickle`/`marshal` loads, or imports `subprocess`, `pickle`, `marshal`, `shelve`, `dill` or `cloudpickle`.

Bounds in code:

| Limit | Value | Where |
|---|---|---|
| Upload size | 50 MB (25 MB recommended on Render lite) | `MAX_UPLOAD_SIZE_MB` |
| Rows inspected | 10,000 per dataset (XLSX: in total across sheets) | `content_checker._MAX_ROWS` |
| XLSX archive | 50 MB compressed, 500 MB declared uncompressed, 10,000 members | `_XLSX_*` |
| Heuristics / YARA read | first 1 MB / 2 MB | `heuristics._MAX_BYTES`, `yara_scanner` |
| PE header search | 256 candidates, e_lfanew ≤ 64 KB | `scanner/pe_detect.py` |

Container confinement in local/full Docker (`docker-compose.yml`, verified 18 Oct 2026 with `docker inspect` and in-container checks): non-root user `aegis` (uid 1000), read-only root filesystem, writes only to the `/app/data` and `/app/db` volumes and a 256 MB `/tmp` tmpfs, all Linux capabilities dropped (`CapEff 0`), `no-new-privileges` (`NoNewPrivs 1`), 1 GB memory, 256 processes. The full end-to-end set (clean, EICAR, formula, malformed, oversized) and history persistence across a restart passed under these settings.

Not confined: outbound network (needed for ClamAV, threat intel and AI), and wall-clock time per parse (a thread cannot be killed safely). Render's free tier does not let us set these container options; there the only bounds are the code limits above and Render's 512 MB.

**Possible next step (not built):** move parsing into a separate worker container with no network, read-only input mount and a hard timeout, returning a validated JSON result. Benefit: a parser crash or hang cannot affect the API. Cost: a second container and roughly 100 MB more memory, which does not fit Render free. Worth doing on the Oracle VM or a paid tier if parsing bugs become a measured problem.

## 2. Test sandbox (development)

- The pytest suite runs without `.env`, with synthetic data only, ClamAV mocked (`conftest.enable_mock_av`, visibly test-only) and every provider mocked through `httpx.MockTransport` or monkeypatched functions; no test needs a live key.
- Failure cases covered: missing keys, 401/403/429/5xx, timeouts, malformed JSON, provider outages, ClamAV unavailable, gateway unauthorized, gateway busy, token over plain HTTP, oversized uploads, EICAR.
- Local Docker with real ClamAV: `docs/ORACLE_CLAMAV_DEPLOYMENT.md` §8 and the Phase A.5 run (`docs/MERGE_NOTES.md`, `docs/RENDER_ORACLE_INTEGRATION.md`); tear down with `docker compose down -v` so no EICAR artifact stays behind.
- `CLAMAV_MOCK_MODE` exists for development only; `/health` reports `av_mock_mode`, and it must stay `false` in any deployment.

## 3. Dynamic malware analysis (not part of Aegis scanning)

Aegis never executes uploads and has no detonation sandbox. ANY.RUN, Joe Sandbox and Hybrid Analysis stay **manual only**: a user may submit a sample themselves after reading that community analyses can be public. If an integration is ever approved it must be off by default, require an explicit per-file user action with disclosure, record consent, destination, artifact SHA-256 and report reference, and never trigger automatically because a heuristic or ClamAV flagged a file. A self-hosted sandbox (e.g. CAPE) would need its own isolated VM and a separate approval.
