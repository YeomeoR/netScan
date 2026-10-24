#!/usr/bin/env bash
# One-command netScan setup for a Raspberry Pi (Raspberry Pi OS / Debian / Ubuntu).
# Run ON the Pi:   curl -fsSL https://raw.githubusercontent.com/YeomeoR/netScan/main/deploy/install-pi.sh | sudo bash
# or from a clone: sudo bash deploy/install-pi.sh
# Installs the CLI + web dashboard as a systemd service (netscan-web) running as an unprivileged user.
set -euo pipefail

REPO="${NETSCAN_REPO:-https://github.com/YeomeoR/netScan.git}"
BRANCH="${NETSCAN_BRANCH:-main}"
DEST="${NETSCAN_DEST:-/opt/netScan}"
HOME_DIR=/var/lib/netscan
PORT="${NETSCAN_PORT:-8787}"
SERVICE=netscan-web

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: sudo bash $0" >&2
  exit 1
fi

echo "==> Installing system packages"
apt-get update -y
apt-get install -y python3 python3-venv python3-pip libpcap0.8 git

echo "==> Creating service user and data dir"
id netscan >/dev/null 2>&1 || useradd --system --home "$HOME_DIR" --shell /usr/sbin/nologin netscan
mkdir -p "$HOME_DIR"
chown netscan: "$HOME_DIR"

echo "==> Fetching netScan into $DEST"
if [ -d "$DEST/.git" ]; then
  git -C "$DEST" fetch origin "$BRANCH"
  git -C "$DEST" checkout "$BRANCH"
  git -C "$DEST" pull --ff-only origin "$BRANCH"
else
  git clone --branch "$BRANCH" "$REPO" "$DEST"
fi

echo "==> Building virtualenv"
python3 -m venv "$DEST/.venv"
"$DEST/.venv/bin/pip" install --upgrade pip
"$DEST/.venv/bin/pip" install "$DEST"

run_as_netscan() { sudo -u netscan env NETSCAN_HOME="$HOME_DIR" "$@"; }

if [ ! -f "$HOME_DIR/config.toml" ]; then
  echo "==> Writing config (auto-detects your subnet and pins the router MAC)"
  run_as_netscan "$DEST/.venv/bin/netscan" --accept-terms init
else
  echo "==> Keeping existing $HOME_DIR/config.toml"
fi

echo "==> Installing systemd unit"
systemctl disable --now netscan >/dev/null 2>&1 || true
sed "s#/opt/netScan#$DEST#g; s#--port 8787#--port $PORT#" "$DEST/deploy/$SERVICE.service" > "/etc/systemd/system/$SERVICE.service"
systemctl daemon-reload
systemctl enable --now "$SERVICE"

for _ in $(seq 1 20); do
  [ -s "$HOME_DIR/web_token" ] && break
  sleep 1
done

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
TOKEN="$(cat "$HOME_DIR/web_token" 2>/dev/null || true)"
echo
echo "netScan dashboard is running."
echo "  Open from any device on your LAN:  http://${IP:-<pi-ip>}:${PORT}/#token=${TOKEN}"
echo "  Token file: $HOME_DIR/web_token   (anyone with it can control the scanner; keep it on your LAN)"
echo "  Logs:       journalctl -u $SERVICE -f"
echo "  Terminal:   sudo -u netscan env NETSCAN_HOME=$HOME_DIR $DEST/.venv/bin/netscan list"
