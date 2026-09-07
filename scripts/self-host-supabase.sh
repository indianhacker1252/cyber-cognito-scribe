#!/usr/bin/env bash
# ============================================================================
# CyberScope — Self-Hosted Supabase installer (Docker-based, distro-agnostic)
# ----------------------------------------------------------------------------
# Works on Ubuntu / Debian / RHEL / Alma / Rocky / Arch — anywhere Docker runs.
# Stands up the full Supabase stack (Postgres + GoTrue + PostgREST + Realtime
# + Storage + Studio + Kong) on your VPS, bound to the machine's public IP.
#
# Usage (as root or via sudo):
#   sudo bash scripts/self-host-supabase.sh
#
# After it finishes it prints:
#   - SUPABASE_URL         (http://<VPS_IP>:8000)
#   - ANON_KEY             (paste into your app's .env as VITE_SUPABASE_PUBLISHABLE_KEY)
#   - SERVICE_ROLE_KEY     (server-side only — never ship to browser)
#   - Postgres connection string (for the migration script)
# ============================================================================
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/supabase}"
SUPA_REPO="https://github.com/supabase/supabase.git"
JWT_SECRET="${JWT_SECRET:-$(openssl rand -hex 32)}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-$(openssl rand -hex 24)}"
DASHBOARD_USER="${DASHBOARD_USER:-admin}"
DASHBOARD_PASSWORD="${DASHBOARD_PASSWORD:-$(openssl rand -hex 12)}"

log() { printf "\033[1;36m[self-host]\033[0m %s\n" "$*"; }
die() { printf "\033[1;31m[error]\033[0m %s\n" "$*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || die "Run as root (use sudo)."

# ---- 1. Install Docker + Compose if missing ------------------------------
install_docker() {
  if command -v docker >/dev/null && docker compose version >/dev/null 2>&1; then
    log "Docker + Compose already present."
    return
  fi
  log "Installing Docker via get.docker.com (works on all major distros)…"
  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker
}
install_docker

# ---- 2. Install helpers --------------------------------------------------
if ! command -v git >/dev/null || ! command -v openssl >/dev/null; then
  if command -v apt-get >/dev/null; then apt-get update && apt-get install -y git openssl jq curl
  elif command -v dnf >/dev/null; then dnf install -y git openssl jq curl
  elif command -v yum >/dev/null; then yum install -y git openssl jq curl
  elif command -v pacman >/dev/null; then pacman -Sy --noconfirm git openssl jq curl
  else die "Install git/openssl/jq/curl manually and re-run."
  fi
fi

# ---- 3. Clone the official Supabase docker bundle ------------------------
mkdir -p "$INSTALL_DIR"
if [ ! -d "$INSTALL_DIR/supabase" ]; then
  log "Cloning Supabase repo into $INSTALL_DIR/supabase …"
  git clone --depth 1 "$SUPA_REPO" "$INSTALL_DIR/supabase"
fi

WORK="$INSTALL_DIR/stack"
mkdir -p "$WORK"
cp -rn "$INSTALL_DIR/supabase/docker/." "$WORK/"
cd "$WORK"

# ---- 4. Detect public IP -------------------------------------------------
PUBLIC_IP="$(curl -fsSL https://api.ipify.org || hostname -I | awk '{print $1}')"
log "Detected public IP: $PUBLIC_IP"

# ---- 5. Mint JWT anon + service-role keys --------------------------------
gen_jwt() {
  local role="$1"
  local now exp header payload sig
  now=$(date +%s); exp=$((now + 60*60*24*365*10))  # 10 years
  header=$(printf '{"alg":"HS256","typ":"JWT"}' | openssl base64 -A | tr '+/' '-_' | tr -d '=')
  payload=$(printf '{"role":"%s","iss":"supabase-selfhosted","iat":%d,"exp":%d}' "$role" "$now" "$exp" \
    | openssl base64 -A | tr '+/' '-_' | tr -d '=')
  sig=$(printf '%s.%s' "$header" "$payload" \
    | openssl dgst -sha256 -hmac "$JWT_SECRET" -binary \
    | openssl base64 -A | tr '+/' '-_' | tr -d '=')
  printf '%s.%s.%s' "$header" "$payload" "$sig"
}
ANON_KEY="$(gen_jwt anon)"
SERVICE_ROLE_KEY="$(gen_jwt service_role)"

# ---- 6. Write .env -------------------------------------------------------
cat > "$WORK/.env" <<EOF
POSTGRES_PASSWORD=$POSTGRES_PASSWORD
JWT_SECRET=$JWT_SECRET
ANON_KEY=$ANON_KEY
SERVICE_ROLE_KEY=$SERVICE_ROLE_KEY

DASHBOARD_USERNAME=$DASHBOARD_USER
DASHBOARD_PASSWORD=$DASHBOARD_PASSWORD

SITE_URL=http://$PUBLIC_IP:3000
API_EXTERNAL_URL=http://$PUBLIC_IP:8000
SUPABASE_PUBLIC_URL=http://$PUBLIC_IP:8000
ADDITIONAL_REDIRECT_URLS=

POSTGRES_HOST=db
POSTGRES_DB=postgres
POSTGRES_PORT=5432

KONG_HTTP_PORT=8000
KONG_HTTPS_PORT=8443
STUDIO_PORT=3000

PGRST_DB_SCHEMAS=public,storage,graphql_public
DISABLE_SIGNUP=false
ENABLE_EMAIL_SIGNUP=true
ENABLE_EMAIL_AUTOCONFIRM=true
ENABLE_ANONYMOUS_USERS=false
JWT_EXPIRY=3600

SMTP_ADMIN_EMAIL=admin@example.com
SMTP_HOST=supabase-mail
SMTP_PORT=2500
SMTP_USER=fake
SMTP_PASS=fake
SMTP_SENDER_NAME=CyberScope
MAILER_URLPATHS_INVITE=/auth/v1/verify
MAILER_URLPATHS_CONFIRMATION=/auth/v1/verify
MAILER_URLPATHS_RECOVERY=/auth/v1/verify
MAILER_URLPATHS_EMAIL_CHANGE=/auth/v1/verify

STUDIO_DEFAULT_ORGANIZATION=CyberScope
STUDIO_DEFAULT_PROJECT=CyberScope

FUNCTIONS_VERIFY_JWT=false
IMGPROXY_ENABLE_WEBP_DETECTION=true
POOLER_TENANT_ID=cyberscope
POOLER_DEFAULT_POOL_SIZE=20
POOLER_MAX_CLIENT_CONN=100
POOLER_PROXY_PORT_TRANSACTION=6543
SECRET_KEY_BASE=$(openssl rand -hex 32)
VAULT_ENC_KEY=$(openssl rand -hex 16)
LOGFLARE_LOGGER_BACKEND_API_KEY=$(openssl rand -hex 16)
LOGFLARE_API_KEY=$(openssl rand -hex 16)
EOF

# ---- 7. Bring the stack up ----------------------------------------------
log "Pulling images (first run takes a few minutes)…"
docker compose pull
log "Starting stack…"
docker compose up -d

# ---- 8. Wait for Postgres to be reachable --------------------------------
log "Waiting for Postgres…"
for i in $(seq 1 60); do
  if docker compose exec -T db pg_isready -U postgres >/dev/null 2>&1; then
    log "Postgres is ready."; break
  fi
  sleep 2
done

# ---- 9. Save credentials & print summary ---------------------------------
CRED_FILE="$INSTALL_DIR/CREDENTIALS.txt"
cat > "$CRED_FILE" <<EOF
=====================================================================
CyberScope Self-Hosted Supabase — credentials  (KEEP THIS SAFE)
=====================================================================
SUPABASE_URL          = http://$PUBLIC_IP:8000
STUDIO_URL            = http://$PUBLIC_IP:3000    (user: $DASHBOARD_USER  pass: $DASHBOARD_PASSWORD)

ANON_KEY              = $ANON_KEY
SERVICE_ROLE_KEY      = $SERVICE_ROLE_KEY   # SERVER ONLY — never in browser
JWT_SECRET            = $JWT_SECRET

POSTGRES_PASSWORD     = $POSTGRES_PASSWORD
POSTGRES_DSN (local)  = postgres://postgres:$POSTGRES_PASSWORD@127.0.0.1:5432/postgres
POSTGRES_DSN (remote) = postgres://postgres:$POSTGRES_PASSWORD@$PUBLIC_IP:5432/postgres

--- Paste into your app's .env ---
VITE_SUPABASE_URL=http://$PUBLIC_IP:8000
VITE_SUPABASE_PUBLISHABLE_KEY=$ANON_KEY
VITE_SUPABASE_PROJECT_ID=selfhosted
=====================================================================
EOF
chmod 600 "$CRED_FILE"

echo
log "DONE. Credentials saved to $CRED_FILE"
echo
cat "$CRED_FILE"
echo
log "Next: run scripts/migrate-to-self-hosted.sh from your workstation to copy data over."
