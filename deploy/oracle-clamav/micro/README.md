# ClamAV on the Oracle Always Free micro VM

Deployed 5 Nov 2026 while A1 (2 OCPU / 12 GB) capacity in Hyderabad was exhausted.

| Item | Value |
|---|---|
| VM | `aegis-clamav-micro`, VM.Standard.E2.1.Micro, Oracle Linux 9.8 x86_64, ~0.5 GB RAM + 4 GB swap |
| Fixed IP | 129.225.105.129 (reserved public IP `aegis-clamav-ip`) |
| URL | https://129-225-105-129.sslip.io (Let's Encrypt via Caddy, TLS-ALPN on 443) |
| ClamAV | 1.4.6 from Oracle EPEL (`ol9_developer_EPEL`): `clamd@scan` on `/run/clamd.scan/clamd.sock`, `clamav-freshclam` daily updates |
| Gateway | `clamd_gateway.py` (Python standard library), 127.0.0.1:8080, systemd `aegis-gateway`, token in `/etc/aegis-gateway.env` (root:clamscan 640) |
| HTTPS | Caddy 2.11.7 from Caddy's official COPR (`@caddy/caddy`), `/etc/caddy/Caddyfile`, domain via `caddy.service.d/domain.conf` |
| Open ports | 22 (owner's IP /32 only), 443. 80 and 3310 closed |

Measured: clamd needs ~22 min to load 3.6 M signatures on this VM (`TimeoutStartSec=45min` override); clean CSV 0.7 s and EICAR 0.9 s end to end over HTTPS; 401 without or with a wrong token; other paths 404; gateway ~20 MB RSS. While clamd reloads after a signature update, scans fail and Aegis falls back to MetaDefender (never "clean").

Render: `AV_PROVIDER=clamav_rest`, `CLAMAV_API_URL=https://129-225-105-129.sslip.io`, `CLAMAV_API_TOKEN` = the VM's `SCAN_GATEWAY_TOKEN`, `AV_FALLBACK_PROVIDER=metadefender`, `AV_REQUIRED=true`.
