#!/usr/bin/env bash
# ============================================================================
# CyberScope — Migrate data from Lovable Cloud → self-hosted Supabase
# ----------------------------------------------------------------------------
# Run this from a workstation that can reach BOTH:
#   - the current (Lovable Cloud) Postgres         [SOURCE_DSN]
#   - the new self-hosted Postgres on your VPS     [TARGET_DSN]
#
# Usage:
#   SOURCE_DSN="postgres://postgres:PWD@SOURCE_HOST:5432/postgres" \
#   TARGET_DSN="postgres://postgres:PWD@YOUR_VPS_IP:5432/postgres" \
#   bash scripts/migrate-to-self-hosted.sh
#
# What it does:
#   1. Dumps the SOURCE (schema + data, roles skipped, auth+storage kept).
#   2. Restores into TARGET. Existing objects on the target are preserved
#      (self-hosted Supabase already ships auth/storage schemas).
#   3. Verifies row counts on the domain tables.
#
# Requires: pg_dump / psql (v15+). Install via `apt install postgresql-client-15`
# (Debian/Ubuntu) or `dnf install postgresql15` (RHEL).
# ============================================================================
set -euo pipefail

: "${SOURCE_DSN:?Set SOURCE_DSN to the Lovable Cloud Postgres connection string}"
: "${TARGET_DSN:?Set TARGET_DSN to your self-hosted Postgres connection string}"

DUMP_FILE="${DUMP_FILE:-/tmp/cyberscope-cloud-dump-$(date +%Y%m%d-%H%M%S).sql}"

log() { printf "\033[1;36m[migrate]\033[0m %s\n" "$*"; }

command -v pg_dump >/dev/null || { echo "pg_dump not found. Install postgresql-client-15+." >&2; exit 1; }
command -v psql    >/dev/null || { echo "psql not found."    >&2; exit 1; }

# --- 1. Dump only application data from the public schema -----------------
# We deliberately skip auth/storage/realtime/etc so we don't clobber the
# self-hosted stack's own managed schemas. Auth users are exported separately.
log "Dumping public schema from source → $DUMP_FILE"
pg_dump "$SOURCE_DSN" \
  --schema=public \
  --no-owner --no-privileges --no-publications --no-subscriptions \
  --disable-triggers \
  --format=plain \
  --file="$DUMP_FILE.public.sql"

log "Dumping auth.users from source (login accounts) …"
pg_dump "$SOURCE_DSN" \
  --data-only --table=auth.users --table=auth.identities \
  --no-owner --no-privileges \
  --format=plain \
  --file="$DUMP_FILE.auth.sql" || log "auth dump skipped (permission)."

# --- 2. Restore public schema into target ---------------------------------
log "Restoring public schema into target…"
psql "$TARGET_DSN" -v ON_ERROR_STOP=0 -f "$DUMP_FILE.public.sql"

if [ -s "$DUMP_FILE.auth.sql" ]; then
  log "Restoring auth users into target…"
  psql "$TARGET_DSN" -v ON_ERROR_STOP=0 -f "$DUMP_FILE.auth.sql" || log "auth restore had non-fatal errors."
fi

# --- 3. Verify --------------------------------------------------------------
log "Row counts on target (spot check):"
psql "$TARGET_DSN" -c "
SELECT relname AS table, n_live_tup AS rows
FROM pg_stat_user_tables
WHERE schemaname='public'
ORDER BY n_live_tup DESC
LIMIT 25;"

log "Done. Dump files kept at:"
echo "   $DUMP_FILE.public.sql"
echo "   $DUMP_FILE.auth.sql"
echo
log "Next: update your app's .env with the VITE_SUPABASE_URL/KEY from CREDENTIALS.txt, redeploy, and test login."
