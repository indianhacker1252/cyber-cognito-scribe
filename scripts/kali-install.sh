#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/cyberscope-agent}"
PORT="${PORT:-8080}"
TOKEN="${WORKER_TOKEN:-$(openssl rand -hex 24)}"

sudo mkdir -p "$APP_DIR"
sudo cp "$(dirname "$0")/cyberscope-agent.py" "$APP_DIR/cyberscope-agent.py"
sudo chmod +x "$APP_DIR/cyberscope-agent.py"

if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-pip curl nmap masscan whatweb wafw00f nikto gobuster dirsearch sslscan testssl.sh sqlmap ffuf
fi

python3 -m pip install --break-system-packages --quiet playwright || true
python3 -m playwright install chromium || true

sudo tee /etc/systemd/system/cyberscope-agent.service >/dev/null <<EOF
[Unit]
Description=CyberScope Local Worker Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
Environment=PORT=$PORT
Environment=WORKER_TOKEN=$TOKEN
ExecStart=/usr/bin/env python3 $APP_DIR/cyberscope-agent.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now cyberscope-agent.service

echo "CyberScope agent is running."
echo "Endpoint URL: http://<this-host>:$PORT"
echo "Auth token: $TOKEN"