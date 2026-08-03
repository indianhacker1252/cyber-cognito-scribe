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

install_local_agent() {
  install_docker
  green "Installing the CyberScope Option-B long-lived agent runtime locally..."
  local RUNTIME_DIR="$ROOT_DIR/runtime"
  if [[ ! -d "$RUNTIME_DIR" ]]; then
    warn "runtime/ directory not found at $RUNTIME_DIR — skipping."
    return
  fi

  local ENV_FILE="$RUNTIME_DIR/.env"
  if [[ ! -f "$ENV_FILE" ]]; then
    green "Configuring runtime/.env — paste the values from Lovable → Project Settings."
    read -rp "SUPABASE_URL (https://xxxx.supabase.co): " SB_URL
    read -rp "SUPABASE_SERVICE_ROLE_KEY: " SB_SRK
    read -rp "LOVABLE_API_KEY (optional, enter to skip): " LOV_KEY
    read -rp "OPENAI_API_KEY (optional): " OAI_KEY
    read -rp "GEMINI_API_KEY (optional): " GEM_KEY
    cat > "$ENV_FILE" <<EOF
SUPABASE_URL=${SB_URL}
SUPABASE_SERVICE_ROLE_KEY=${SB_SRK}
LOVABLE_API_KEY=${LOV_KEY}
OPENAI_API_KEY=${OAI_KEY}
GEMINI_API_KEY=${GEM_KEY}
RUNTIME_HOST_ID=$(hostname)-$(openssl rand -hex 3)
POLL_INTERVAL_MS=3000
EOF
    green "Wrote $ENV_FILE"
  else
    green "Reusing existing $ENV_FILE"
  fi

  local REPLICAS=1
  yellow "How many parallel agent workers to run? [1]: "
  read -r REPLICAS || true
  REPLICAS="${REPLICAS:-1}"

  ( cd "$RUNTIME_DIR" && \
    if docker compose version >/dev/null 2>&1; then
      sudo_cmd docker compose up -d --build --scale agent="$REPLICAS"
    else
      sudo_cmd docker-compose up -d --build --scale agent="$REPLICAS"
    fi )

  green "Local agent runtime is up. It will poll agent_sessions and pick up queued scans within ~3s."
  green "Logs:  cd $RUNTIME_DIR && sudo docker compose logs -f agent"
}

install_ollama() {
  if command -v ollama >/dev/null 2>&1; then green "Ollama already installed."; else
    green "Installing Ollama..."
    curl -fsSL https://ollama.com/install.sh | sh || warn "Ollama install failed"
  fi
  green "Pulling recommended local models (this can take a while)..."
  for m in qwen2.5-coder:7b llama3.1:8b nomic-embed-text; do
    ollama pull "$m" || warn "pull $m failed"
  done
  if ask "Also pull deepseek-r1:7b (reasoning)?" Y; then ollama pull deepseek-r1:7b || true; fi
  if ask "Machine has 24GB+ VRAM — pull qwen2.5:32b (heavy)?" n; then ollama pull qwen2.5:32b || true; fi
}

install_pd_suite() {
  green "Installing ProjectDiscovery suite (subfinder, httpx, dnsx, naabu, katana, nuclei)..."
  if ! command -v go >/dev/null 2>&1; then
    sudo_cmd apt-get install -y golang-go || true
  fi
  export GOBIN=/usr/local/bin
  for pkg in \
    github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    github.com/projectdiscovery/httpx/cmd/httpx@latest \
    github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
    github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
    github.com/projectdiscovery/katana/cmd/katana@latest \
    github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    github.com/tomnomnom/assetfinder@latest \
    github.com/tomnomnom/waybackurls@latest \
    github.com/lc/gau/v2/cmd/gau@latest ; do
    sudo_cmd env GOBIN=/usr/local/bin go install "$pkg" || warn "install $pkg failed"
  done
}

install_exploit_clis() {
  green "Installing exploitation CLIs..."
  sudo_cmd apt-get install -y sqlmap commix wpscan feroxbuster || true
  export GOBIN=/usr/local/bin
  sudo_cmd env GOBIN=/usr/local/bin go install github.com/hahwul/dalfox/v2@latest || true
  sudo_cmd env GOBIN=/usr/local/bin go install github.com/s0md3v/Arjun@latest || true
}

install_nuclei_templates() {
  green "Updating nuclei templates..."
  nuclei -update-templates || warn "nuclei template update failed"
}

start_interactsh() {
  green "Starting self-hosted interactsh-server (OOB)..."
  sudo_cmd docker run -d --restart unless-stopped --name cyberscope-interactsh \
    -p 8443:443 -p 8853:53/udp \
    projectdiscovery/interactsh-server:latest \
    -domain "$(hostname -I | awk '{print $1}').nip.io" || warn "interactsh already running or failed"
  green "OOB base: http://$(hostname -I | awk '{print $1}'):8443"
}

start_mitm() {
  green "Starting mitmproxy sidecar (request interception/replay)..."
  sudo_cmd docker run -d --restart unless-stopped --name cyberscope-mitm \
    -p 8081:8081 -p 8082:8080 \
    mitmproxy/mitmproxy mitmweb --web-host 0.0.0.0 --web-port 8081 --listen-port 8080 \
    || warn "mitmproxy already running or failed"
  green "mitmweb UI: http://$(hostname -I | awk '{print $1}'):8081"
}

register_systemd() {
  green "Registering cyberscope-agent systemd unit for auto-boot..."
  sudo_cmd tee /etc/systemd/system/cyberscope-agent-runtime.service >/dev/null <<EOF
[Unit]
Description=CyberScope Option-B Agent Runtime (Docker Compose)
After=docker.service network-online.target
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$ROOT_DIR/runtime
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down

[Install]
WantedBy=multi-user.target
EOF
  sudo_cmd systemctl daemon-reload
  sudo_cmd systemctl enable --now cyberscope-agent-runtime.service
}

scale_replicas() {
  local n; n="$(( $(nproc) / 2 ))"; [[ $n -lt 1 ]] && n=1; [[ $n -gt 8 ]] && n=8
  green "Scaling agent runtime to ${n} replicas..."
  ( cd "$ROOT_DIR/runtime" && sudo_cmd docker compose up -d --scale agent="$n" )
}

run_doctor() {
  green "Running selftest..."
  ( cd "$ROOT_DIR/runtime" && sudo_cmd docker compose exec -T agent tsx src/selftest.ts ) \
    || warn "selftest reported failures — see output above"
}

main() {
  echo "CyberScope guided installer"
  echo "This script asks before each major requirement. Run on Debian/Ubuntu/Kali."
  ask "Install Docker / Compose if missing?" Y && install_docker
  ask "Install security scanner CLI tools (nmap, nikto, ffuf, etc.)?" Y && install_security_tools
  ask "Install Playwright Chromium for browser-based testing?" Y && install_playwright
  ask "Install Ollama and pull recommended local models (qwen2.5-coder, llama3.1)?" Y && install_ollama
  ask "Install ProjectDiscovery suite (subfinder/httpx/nuclei/katana/…)?" Y && install_pd_suite
  ask "Install exploitation CLIs (sqlmap/dalfox/commix/…)?" Y && install_exploit_clis
  ask "Update nuclei templates?" Y && install_nuclei_templates
  ask "Start self-hosted interactsh-server for OOB callbacks?" Y && start_interactsh
  ask "Start mitmproxy sidecar for request interception/replay?" Y && start_mitm
  ask "Start the bundled Docker stack (local database + Ollama + worker)?" Y && start_stack
  ask "Install the native systemd worker service too?" n && install_systemd_worker
  ask "Install & start the long-lived Option-B agent runtime locally?" Y && install_local_agent
  ask "Register agent runtime as systemd (auto-boot on reboot)?" Y && register_systemd
  ask "Auto-scale agent replicas to $(( $(nproc) / 2 )) workers?" Y && scale_replicas
  ask "Run selftest (doctor) now?" Y && run_doctor
  green "Done. Paste the printed Worker, Database, Local AI, and interactsh values into Settings."
  green "Then in the app: open a target → Start Agent Scan — the local runtime will claim it."
}

main "$@"
