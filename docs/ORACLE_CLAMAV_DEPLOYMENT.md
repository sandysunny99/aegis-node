# Oracle ClamAV deployment

Real ClamAV on an Oracle Cloud Always Free Arm VM, reachable only through an authenticated HTTPS gateway. The Render backend sends each uploaded file to this service and gets back ClamAV's verdict. Files go only to your own VM, never to a third party.

Status: **designed and tested locally (amd64, Docker Desktop), not yet deployed.** Every step below that needs your Oracle account, DNS or secrets is marked **(you)**.

## 1. What runs on the VM

```
Render (Aegis backend)
   │  HTTPS, Authorization: Bearer <SCAN_GATEWAY_TOKEN>
   ▼
caddy:2.10.2            :80 (ACME + redirect), :443 (TLS)   ← the only published ports
   │  private Docker network "scan"
   ▼
scan-gateway            token check (constant time), 50 MB cap, 30 req/min, 2 concurrent scans
   ▼
benzino77/clamav-rest-api:1.6.15   multipart field FILES
   ▼
clamav/clamav-debian:1.5.4         clamd 3310 (never published) + the image's own freshclam
```

Files: `deploy/oracle-clamav/` (`docker-compose.yml`, `Caddyfile`, `clamav/clamd.conf`, `gateway/`, `.env.example`). All images are pinned and publish `linux/arm64` (checked with `docker manifest inspect`, 15–17 Oct 2026). `clamav/clamav` is amd64-only, so the Debian variant is used.

Gateway routes: `GET /healthz` (no auth, returns only `{"status":"ok"}`), `GET /api/v1/version` and `POST /api/v1/scan` (token required). Every other path is 404, so it cannot be used as a proxy. Logs never contain the token (Caddy shows it as `REDACTED`), file names or contents. The gateway renames every upload to `upload.bin` before it reaches ClamAV.

## 2. Oracle Always Free facts (official, read 17 Oct 2026)

Source: https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm

- Ampere A1: 1,500 OCPU hours and 9,000 GB hours a month, "equivalent to 2 OCPUs and 12 GB of memory" for Always Free tenancies.
- 200 GB combined boot and block volume storage, 10 TB outbound data a month.
- Idle reclamation: an instance is idle if, over 7 days, 95th-percentile CPU is under 20 %, network under 20 % and (A1 only) memory under 20 %. ClamAV keeps about 1 GB resident (measured below), which is under 20 % of 12 GB, so a mostly idle scan VM can still be reclaimed. Keep a copy of `.env` off the VM and see section 7.
- Not verified here: current A1 capacity in your home region ("Out of host capacity" is a known issue; retry or pick another availability domain).

## 3. Measured locally (Docker Desktop, amd64, 17 Oct 2026)

| Check | Result |
|---|---|
| ClamAV version via authenticated `/api/v1/version` | `ClamAV 1.5.4/28151/Mon Oct 12 2026` |
| No token / wrong token / token without `Bearer` | 401 on scan and version |
| Harmless CSV | `is_infected: false`, 77 ms |
| EICAR as the whole file | `is_infected: true`, `Eicar-Test-Signature` |
| EICAR inside a CSV row | **not detected by ClamAV** (the EICAR signature only matches at the start of a file); Aegis still flags it through YARA-002 and MAL-001 |
| 51 MB upload | 413 |
| `/docs`, path traversal, other paths | 404 |
| Scan time (1 / 10 / 25 / 49 MB) | 0.1 / 0.7 / 1.1 / 3.5 s |
| Memory at rest | clamd 994 MiB, clamav-rest 122 MiB, gateway 43 MiB, Caddy 13 MiB |
| Aegis `ClamAVRestProvider` through the gateway with verified TLS | ping, version, harmless scan OK; wrong token → unavailable; token over `http://` → refused before sending |

Not measured: memory during a signature reload (the ClamAV docs say a second copy can be loaded; `ConcurrentDatabaseReload no` in `clamav/clamd.conf` avoids that at the cost of a short scanning pause). The compose file caps clamd at 3 GB. The often quoted "3–4 GiB" requirement is not validated by these numbers.

## 4. Set up the VM (you)

1. In the Oracle console, create a `VM.Standard.A1.Flex` instance (2 OCPU, 12 GB) with Ubuntu 24.04 (aarch64). Keep the SSH key.
2. VCN security list / NSG: allow inbound TCP 22 from your IP only, TCP 80 and 443 from anywhere. Nothing else. Do **not** open 3000 or 3310.
3. On the VM, Ubuntu's own firewall also blocks ports; open 80 and 443 there:
   ```bash
   sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 80 -j ACCEPT
   sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 443 -j ACCEPT
   sudo netfilter-persistent save
   ```
4. Install Docker Engine and the Compose plugin from Docker's apt repository (https://docs.docker.com/engine/install/ubuntu/).
5. Point a DNS name at the VM's public IP (any domain you control, or a free dynamic-DNS name). Caddy needs it to get a Let's Encrypt certificate.

## 5. Start the service (you)

```bash
git clone https://github.com/sandysunny99/aegis-node.git && cd aegis-node/deploy/oracle-clamav
cp .env.example .env
openssl rand -base64 48            # paste as SCAN_GATEWAY_TOKEN in .env
nano .env                          # set SCAN_DOMAIN; leave CADDY_TLS_DIRECTIVE empty
chmod 600 .env
docker compose up -d --build
docker compose ps                  # clamav becomes healthy after the first signature download (a few minutes)
```

Expected checks from your laptop:

```bash
curl https://SCAN_DOMAIN/healthz                                                   # {"status":"ok"}
curl -H "Authorization: Bearer $TOKEN" https://SCAN_DOMAIN/api/v1/version           # {"success":true,"data":{"version":"ClamAV 1.5.4/..."}}
curl -o /dev/null -w "%{http_code}\n" https://SCAN_DOMAIN/api/v1/version            # 401
```

Then set the same token in Render (see `docs/RENDER_ORACLE_INTEGRATION.md`).

## 6. Operations

- **Signatures**: the ClamAV image runs freshclam itself and keeps `/var/lib/clamav` on the `clamav_db` volume, so signatures survive `docker compose up -d` after an image update. Do not run a second freshclam. The signature number and date appear in `/api/v1/version` and in Aegis' `/health/detectors`.
- **Restart behaviour**: everything is `restart: unless-stopped`. If clamav-rest starts before clamd listens it exits and Docker restarts it (seen locally after `docker restart`); until then scans are reported as `CLAMAV_UNAVAILABLE`, never clean.
- **Logs**: `docker compose logs --tail 50 scan-gateway caddy`.
- **Token rotation**: generate a new token, update `.env` on the VM and `CLAMAV_API_TOKEN` in Render, then `docker compose up -d scan-gateway`.
- **Updates**: change the pinned tags in `docker-compose.yml`, run the local test first, then `docker compose pull && docker compose up -d`.

## 7. Backup and recovery

Only two things need backing up: the `.env` file (keep it in a password manager) and nothing else. Signatures re-download on a fresh VM and Caddy re-issues the certificate. If Oracle reclaims the VM, repeat sections 4 and 5; Aegis reports ClamAV as unavailable in the meantime.

## 8. Local test without a domain

```bash
cd deploy/oracle-clamav
printf 'SCAN_GATEWAY_TOKEN=%s\nSCAN_DOMAIN=localhost\nCADDY_TLS_DIRECTIVE=tls internal\n' "$(openssl rand -base64 48)" > .env
docker compose up -d --build       # then call https://localhost with curl -k
docker compose down -v
```
