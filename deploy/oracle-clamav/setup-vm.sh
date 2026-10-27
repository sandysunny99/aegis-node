#!/usr/bin/env bash
# One-time setup of the Aegis ClamAV scan gateway on an Oracle Cloud Ubuntu 24.04 Arm VM.
#
#   curl -fsSL https://raw.githubusercontent.com/sandysunny99/aegis-node/main/deploy/oracle-clamav/setup-vm.sh -o setup-vm.sh
#   bash setup-vm.sh                    # uses <public-ip>.sslip.io as the HTTPS name
#   bash setup-vm.sh scan.example.org   # or your own DNS name pointing at this VM
#
# What it does: opens 80/443 in the VM firewall (never 3000 or 3310), installs Docker
# from Docker's apt repository, clones the repo, writes deploy/oracle-clamav/.env with
# a fresh random token (mode 600), starts Caddy + gateway + ClamAV, and waits until
# https://<name>/healthz answers. Safe to re-run: an existing .env and token are kept.
set -euo pipefail

REPO_URL="https://github.com/sandysunny99/aegis-node.git"
APP_DIR="${HOME}/aegis-node"
DEPLOY_DIR="${APP_DIR}/deploy/oracle-clamav"

say() { printf '\n==> %s\n' "$*"; }

if [ "$(uname -m)" != "aarch64" ] && [ "$(uname -m)" != "x86_64" ]; then
  echo "Unsupported CPU architecture: $(uname -m)" >&2
  exit 1
fi

say "Opening TCP 80 and 443 in the VM firewall (Oracle's Ubuntu image blocks them by default)"
sudo apt-get update -y
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent ca-certificates curl git openssl
for port in 80 443; do
  if ! sudo iptables -C INPUT -m state --state NEW -p tcp --dport "$port" -j ACCEPT 2>/dev/null; then
    sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport "$port" -j ACCEPT
  fi
done
sudo netfilter-persistent save

if ! command -v docker >/dev/null 2>&1; then
  say "Installing Docker Engine and the Compose plugin from Docker's apt repository"
  sudo install -m 0755 -d /etc/apt/keyrings
  sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  sudo chmod a+r /etc/apt/keyrings/docker.asc
  # shellcheck disable=SC1091
  . /etc/os-release
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
    | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
  sudo apt-get update -y
  sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
DOCKER="sudo docker"

say "Fetching the gateway files"
if [ -d "${APP_DIR}/.git" ]; then
  git -C "$APP_DIR" pull --ff-only
else
  git clone --depth 1 "$REPO_URL" "$APP_DIR"
fi
cd "$DEPLOY_DIR"

DOMAIN="${1:-}"
if [ -z "$DOMAIN" ]; then
  PUBLIC_IP="$(curl -fsS https://checkip.amazonaws.com | tr -d '[:space:]')"
  DOMAIN="$(echo "$PUBLIC_IP" | tr '.' '-').sslip.io"
fi

if [ ! -f .env ]; then
  say "Writing .env with a new random token"
  umask 077
  {
    echo "SCAN_GATEWAY_TOKEN=$(openssl rand -base64 48 | tr -d '\n')"
    echo "SCAN_DOMAIN=${DOMAIN}"
    echo "CADDY_TLS_DIRECTIVE="
    echo "MAX_UPLOAD_MB=50"
    echo "RATE_LIMIT_PER_MINUTE=30"
    echo "MAX_CONCURRENT_SCANS=2"
  } > .env
  chmod 600 .env
else
  say "Keeping the existing .env (token unchanged)"
  DOMAIN="$(grep '^SCAN_DOMAIN=' .env | cut -d= -f2-)"
fi

say "Starting Caddy, the scan gateway and ClamAV"
$DOCKER compose up -d --build

say "Waiting for https://${DOMAIN}/healthz (certificate and first signature download take a few minutes)"
for _ in $(seq 1 60); do
  if curl -fsS --max-time 10 "https://${DOMAIN}/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 10
done

TOKEN="$(grep '^SCAN_GATEWAY_TOKEN=' .env | cut -d= -f2-)"
VERSION="$(curl -fsS --max-time 20 -H "Authorization: Bearer ${TOKEN}" "https://${DOMAIN}/api/v1/version" || true)"
UNAUTH="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "https://${DOMAIN}/api/v1/version" || true)"

echo
echo "------------------------------------------------------------------"
echo "Gateway URL      : https://${DOMAIN}"
echo "ClamAV version   : ${VERSION:-not ready yet, re-run: curl -H \"Authorization: Bearer \$TOKEN\" https://${DOMAIN}/api/v1/version}"
echo "Without token    : HTTP ${UNAUTH} (expected 401)"
echo
echo "Put these in Render -> Environment (the token is a secret; do not paste it in chat):"
echo "  CLAMAV_API_URL=https://${DOMAIN}"
echo "  CLAMAV_API_TOKEN=<the value of SCAN_GATEWAY_TOKEN in ${DEPLOY_DIR}/.env>"
echo "Show the token on this VM with:  grep SCAN_GATEWAY_TOKEN ${DEPLOY_DIR}/.env"
echo "------------------------------------------------------------------"
