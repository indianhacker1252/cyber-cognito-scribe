#!/usr/bin/env bash
# CyberScope Self-Host Installer (Kali/Debian/Ubuntu)
# Idempotent: safe to re-run.
set -euo pipefail

cd "$(dirname "$0")"

log() { printf "\e[1;32m[+]\e[0m %s\n" "$*"; }
warn(){ printf "\e[1;33m[!]\e[0m %s\n" "$*"; }
err() { printf "\e[1;31m[x]\e[0m %s\n" "$*" >&2; }

require_root() { if [ "$EUID" -ne 0 ]; then exec sudo -E "$0" "$@"; fi; }
require_root "$@"

# 1. Docker
if ! command -v docker >/dev/null 2>&1; then
  log "Installing Docker..."
  apt-get update -y
  apt-get install -y ca-certificates curl gnupg lsb-release
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg || true
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(. /etc/os-release && echo "${VERSION_CODENAME:-bookworm}") stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin || apt-get install -y docker.io docker-compose
else
  log "Docker present."
fi

# 2. Worker token
if [ ! -f .worker_token ]; then
  TOKEN=$(openssl rand -hex 24)
  echo "$TOKEN" > .worker_token
  log "Generated worker token: .worker_token"
else
  TOKEN=$(cat .worker_token)
  log "Reusing existing worker token."
fi
export WORKER_TOKEN="$TOKEN"

# 3. Bring up the stack
log "Starting Docker stack (postgres + ollama + worker)..."
if docker compose version >/dev/null 2>&1; then
  WORKER_TOKEN="$TOKEN" docker compose up -d --build
else
  WORKER_TOKEN="$TOKEN" docker-compose up -d --build
fi

# 4. Wait for ollama and pull models (init container handles this; we tail status)
log "Pulling local AI models in background (llama3.1:8b + qwen2.5-coder:7b). This may take a while on first run."

# 5. Print connection details
IP=$(hostname -I | awk '{print $1}')
cat <<EOF

============================================================
 CyberScope local stack is up.

 Worker  URL : http://${IP}:8080
 Worker token: ${TOKEN}
 Postgres    : postgres://cyberscope:cyberscope@${IP}:5544/cyberscope
 Local AI    : http://${IP}:11434/v1   (OpenAI-compatible)

 Paste these into  Settings → External Infrastructure
 and  Settings → External Database.
============================================================

EOF
