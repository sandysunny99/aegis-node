# Deployment runbook

Single Render Docker service (frontend + API), Oracle VM for ClamAV later. Every step that touches GitHub, Render or Oracle needs the owner's explicit approval first.

## 1. Push (after approval of the Gate I report)

```bash
git push -u origin integrate/core-audit
git push -u origin feat/bastion-frontend
git push -u origin release/2026-10-core-bastion
```

No force pushes, no tag pushes. Then open pull requests: `integrate/core-audit → main` (backend), `feat/bastion-frontend → main` (UI) for review, and `release/2026-10-core-bastion → main` as the one to merge. Do not auto-merge. Verify each remote head equals the local commit (`git ls-remote origin <branch>`).

## 2. Preview on Render

Render deploys `main` from `render.yaml`. For a preview without touching production: create a second Render web service from the same repo pointing at `release/2026-10-core-bastion` (or use Render preview environments if the plan has them). Set the same secrets as production through the dashboard; add the preview's own `https://<preview>.onrender.com` to `ALLOWED_ORIGINS` and to the Turnstile allowed hostnames.

Expected after deploy: `GET /health` → `status ok`, `max_file_size_mb 25`; `GET /health/detectors` → `profile lite`, ClamAV entry shows `metadefender`, all optional providers `enabled false`, `database.persistent false` (unless PostgreSQL is approved).

## 3. Smoke test (preview)

Upload a harmless CSV in the UI, scan, open the dataset page, History, and the scan timeline; confirm "What was checked" shows MetaDefender's real state (a new dataset hash is "not found", so the verdict is "Clean, with limitations"), threat intel "Off", and the temporary-storage warning. Record the deployed commit (`Render → Events`). Record results in `docs/release/SMOKE_TEST_REPORT.md`.

## 4. Production

Merge the release PR into `main` (owner), Render auto-deploys. Repeat section 3 against `https://aegis-node.onrender.com`. Watch the Render logs for 15 minutes for 5xx, timeouts and memory restarts.

## 5. Switching to Oracle ClamAV (later, separate approval)

Only after `docs/ORACLE_CLAMAV_DEPLOYMENT.md` sections 4–5 are done and a harmless file and EICAR were scanned through the preview service with the gateway: set `AV_PROVIDER=clamav_rest`, `CLAMAV_API_URL=https://<domain>`, `CLAMAV_API_TOKEN` (secret) on the preview, verify, then on production.

## 6. Rollback

- **Code:** Render → Events → "Rollback" to the previous deploy (keeps env vars), or revert the merge commit on `main` with `git revert -m 1 <merge>` and push (no force).
- **Antivirus switch:** set `AV_PROVIDER` back to `metadefender` in the dashboard and redeploy.
- **Data:** none to roll back on Render free (SQLite in `/tmp`). With PostgreSQL, the new columns and `scan_events` table are additive; older code ignores them. Do not drop tables during a rollback.
