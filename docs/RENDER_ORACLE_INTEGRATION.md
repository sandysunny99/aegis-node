# Render ↔ Oracle ClamAV integration

Request path: **Vercel frontend → Render Aegis backend → HTTPS + bearer token → Oracle scan gateway → clamav-rest → clamd.**

Status: code and tests are in place on `integrate/core-audit`; **nothing is deployed** and `render.yaml` has **not** been changed (it still selects MetaDefender; see "Decision needed").

## 1. Configuration (Render dashboard or `render.yaml`)

| Variable | Value | Notes |
|---|---|---|
| `AEGIS_PROFILE` | `lite` | Reported by `/health/detectors`; Render free tier |
| `AV_PROVIDER` | `clamav_rest` | The existing provider; no new provider type was needed |
| `CLAMAV_API_URL` | `https://<SCAN_DOMAIN>` | Must be HTTPS when a token is set, or every scan is refused and reported unavailable |
| `AV_FALLBACK_PROVIDER` | `metadefender` | Used only when the gateway gives no result (VM down, reclaimed, timeout). The scan report names the provider that answered; if neither answers, ClamAV's reason is kept and the scan is never clean |
| `CLAMAV_API_TOKEN` | secret, same as `SCAN_GATEWAY_TOKEN` on the VM | `sync: false`; also read from `/etc/secrets/CLAMAV_API_TOKEN`. Never a `VITE_*` variable |
| `CLAMAV_MOCK_MODE` | `false` | |
| `MAX_UPLOAD_SIZE_MB` | `25` | From the 512 MB measurement below |
| `DATABASE_URL` | external Postgres URL (e.g. Neon) | Optional; without it history lives in `/tmp` and is lost on restart |
| `R2_*` | Cloudflare R2 settings | Optional; without them uploaded files are temporary |

Mapping to the names suggested in the prompt: `CLAMAV_REMOTE_BASE_URL` → `CLAMAV_API_URL`, `CLAMAV_REMOTE_AUTH_TOKEN` → `CLAMAV_API_TOKEN`. Timeouts are fixed in code (3 s for health, 60 s per scan). `CLAMAV_MAX_CONCURRENCY` is enforced on the VM by the gateway (`MAX_CONCURRENT_SCANS=2`, then 503). `CLAMAV_REMOTE_REQUIRED` is not needed: ClamAV is always required for `clean_verified`, and its absence is always reported.

## 2. Failure semantics (tested)

| Situation | Aegis result |
|---|---|
| Gateway unreachable, 5xx, 401/403, timeout | `CLAMAV_UNAVAILABLE` → best verdict `clean_with_limitations`, stored status `clean_limited`; malicious local findings still give `malicious` |
| Token set but URL is `http://` | Scan not sent; `CLAMAV_UNAVAILABLE` |
| Gateway busy (503) or rate-limited (429) | `CLAMAV_UNAVAILABLE` for that scan |
| Remediation re-scan without ClamAV | `unverified` / `remediated_unverified`, never `completed` |
| ClamAV down | No mock fallback, no upload to any other service |

Tests: `tests/test_clamav_remote_gateway.py`, `tests/test_scan_gateway.py`, `tests/test_core_status_truth.py`. `/health` caches the AV status for up to 5 minutes (audit S8), so it can briefly lag a real outage; each scan checks ClamAV live.

## 3. Lite memory measurement (512 MB container, AV off, 15 Oct 2026)

`docker run --memory=512m`, one fresh container per file, cgroup `memory.peak` after upload + scan. Synthetic data only.

| Format | ~5 MB | ~10 MB | ~25 MB | largest accepted |
|---|---|---|---|---|
| CSV | 205 | 184 | 243 | — (50.2 MB → 413) |
| JSON | 168 | 209 | 328 (27 MB) | — |
| JSONL | 181 (7 MB) | 252 (15 MB) | 372 (37 MB) | — |
| Parquet | 193 | 176 | 268 (28 MB) | — |
| TXT | 149 | 164 | 238 | 358 (48 MB) |
| XLSX | 151 (2.6 MB) | 155 (5.3 MB) | 180 (13 MB) | — |

Peak MiB; baseline after start ≈115 MiB. No container was OOM-killed. The largest peak, 372 MiB for a 37 MB JSONL file, leaves ~140 MiB headroom. **Chosen lite cap: 25 MB**, which keeps every measured format under ~330 MiB. Not measured: concurrent scans on Render, which would add up.

## 4. Decision needed

**Decision 27 Oct 2026 (owner): run without ClamAV for now.** `AV_REQUIRED=false` in `render.yaml`. MetaDefender (hash lookup) and the threat-intelligence providers (VirusTotal, Hybrid Analysis, MalwareBazaar, ThreatFox, YARAify, OTX, CIRCL, URLhaus, urlscan.io) answer instead; scans carry `AV_SIGNATURE_SCAN_OFF` and stay `clean_with_limitations`, never `clean_verified`, because no engine read the file. The Oracle gateway (`deploy/oracle-clamav/setup-vm.sh`) stays available: deploy it, set `CLAMAV_API_URL`, `CLAMAV_API_TOKEN`, `AV_PROVIDER=clamav_rest` and `AV_REQUIRED=true`.

`render.yaml` currently sets `AV_PROVIDER=metadefender`. MetaDefender is now hash-only, so on Render almost every dataset returns `METADEFENDER_HASH_NOT_FOUND` and is `clean_limited`. Switching to the Oracle gateway needs the VM to exist first. Options:

1. Keep MetaDefender until the VM is live, then switch (recommended).
2. Switch now; every Render scan says ClamAV unavailable until the VM is up.

## 5. Rollback

Set `AV_PROVIDER` back to its previous value in the Render dashboard and redeploy. No data migration is involved.
