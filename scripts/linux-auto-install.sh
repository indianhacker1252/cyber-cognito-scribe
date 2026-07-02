#!/usr/bin/env bash
# CyberScope guided Linux installer.
# Installs only what the operator approves: Docker stack, local AI, database,
# Kali/security tools, browser automation, and optional systemd worker.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="${APP_DIR:-/opt/cyberscope-agent}"
PORT="${PORT:-8080}"

green() { printf "\033[1;32m[+]\033[0m %s\n" "$*"; }
yellow(){ printf "\033[1;33m[?]\033[0m %s" "$*"; }
warn() { printf "\033[1;33m[!]\033[0m %s\n" "$*"; }

ask() {
  local prompt="$1" default="${2:-Y}" answer
  yellow "$prompt [$default/n]: "
  read -r answer || true
  answer="${answer:-$default}"
  [[ "$answer" =~ ^[Yy]$|^[Yy][Ee][Ss]$ ]]
}

sudo_cmd() {
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then "$@"; else sudo "$@"; fi
}

install_docker() {
  if command -v docker >/dev/null 2>&1; then green "Docker already installed."; return; fi
  green "Installing Docker and Compose plugin..."
  sudo_cmd apt-get update -y
  sudo_cmd apt-get install -y ca-certificates curl gnupg lsb-release openssl
  sudo_cmd install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/debian/gpg | sudo_cmd gpg --dearmor -o /etc/apt/keyrings/docker.gpg || true
  sudo_cmd chmod a+r /etc/apt/keyrings/docker.gpg || true
  local codename
  codename="$(. /etc/os-release && echo "${VERSION_CODENAME:-bookworm}")"
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian ${codename} stable" | sudo_cmd tee /etc/apt/sources.list.d/docker.list >/dev/null || true
  sudo_cmd apt-get update -y || true
  sudo_cmd apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin || sudo_cmd apt-get install -y docker.io docker-compose
}

install_security_tools() {
  green "Installing local scanning tools..."
  sudo_cmd apt-get update -y
  sudo_cmd DEBIAN_FRONTEND=noninteractive apt-get install -y \
    python3 python3-pip python3-venv curl git nmap masscan whatweb wafw00f nikto \
    gobuster dirsearch sslscan testssl.sh sqlmap ffuf nuclei jq unzip openssl || true
}

install_playwright() {
  green "Installing Python Playwright + Chromium..."
  python3 -m pip install --break-system-packages --quiet playwright || python3 -m pip install --user --quiet playwright
  python3 -m playwright install chromium || true
}

start_stack() {
  install_docker
  green "Starting local Postgres + Ollama + CyberScope worker stack..."
  cd "$ROOT_DIR/deploy"
  if [[ ! -f .worker_token ]]; then openssl rand -hex 24 > .worker_token; fi
  local token ip
  token="$(cat .worker_token)"
  if docker compose version >/dev/null 2>&1; then
    WORKER_TOKEN="$token" docker compose up -d --build
  else
    WORKER_TOKEN="$token" docker-compose up -d --build
  fi
  ip="$(hostname -I | awk '{print $1}')"
  cat <<EOF

Local stack ready:
  Worker URL : http://${ip}:8080
  Worker token: ${token}
  Database   : postgres://cyberscope:cyberscope@${ip}:5544/cyberscope
  Local AI   : http://${ip}:11434/v1
EOF
}

install_systemd_worker() {
  green "Installing native CyberScope worker service..."
  sudo_cmd mkdir -p "$APP_DIR"
  sudo_cmd cp "$ROOT_DIR/scripts/cyberscope-agent.py" "$APP_DIR/cyberscope-agent.py"
  sudo_cmd chmod +x "$APP_DIR/cyberscope-agent.py"
  local token
  token="${WORKER_TOKEN:-$(openssl rand -hex 24)}"
  sudo_cmd tee /etc/systemd/system/cyberscope-agent.service >/dev/null <<EOF
[Unit]
Description=CyberScope Local Worker Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
Environment=PORT=$PORT
Environment=WORKER_TOKEN=$token
ExecStart=/usr/bin/env python3 $APP_DIR/cyberscope-agent.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
  sudo_cmd systemctl daemon-reload
  sudo_cmd systemctl enable --now cyberscope-agent.service
  green "Native worker running on port ${PORT}. Token: ${token}"
}

main() {
  echo "CyberScope guided installer"
  echo "This script asks before each major requirement. Run on Debian/Ubuntu/Kali."
  ask "Install Docker / Compose if missing?" Y && install_docker
  ask "Install security scanner CLI tools (nmap, nuclei, sqlmap, ffuf, etc.)?" Y && install_security_tools
  ask "Install Playwright Chromium for browser-based testing?" Y && install_playwright
  ask "Start the bundled Docker stack (local database + Ollama + worker)?" Y && start_stack
  ask "Install the native systemd worker service too?" n && install_systemd_worker
  green "Done. Paste the printed Worker, Database, and Local AI values into Settings."
}

main "$@"