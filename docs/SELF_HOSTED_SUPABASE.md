# Self-Hosted Supabase on your VPS (Option A)

Kills the auto-pause problem. Runs the full Supabase stack on your machine so
the database, auth, MCP endpoint, and cron jobs stay up 24/7.

Works on any Linux distro that can run Docker (Ubuntu / Debian / RHEL / Alma
/ Rocky / Arch).

---

## 1. Install on the VPS

SSH into the VPS as root (or a sudo user), then:

```bash
git clone <your-repo-url> cyberscope && cd cyberscope
sudo bash scripts/self-host-supabase.sh
```

The script:

- installs Docker + Compose if missing,
- pulls the official Supabase Docker bundle into `/opt/supabase`,
- mints fresh `JWT_SECRET`, `ANON_KEY`, `SERVICE_ROLE_KEY`,
- binds the API to `http://<VPS_PUBLIC_IP>:8000` and Studio to `:3000`,
- writes all credentials to `/opt/supabase/CREDENTIALS.txt` (chmod 600).

Open firewall ports on the VPS: **8000** (API), **3000** (Studio),
**5432** (Postgres — restrict by IP if possible).

---

## 2. Migrate data from Lovable Cloud

From any workstation that can reach both databases:

```bash
SOURCE_DSN="postgres://postgres:<CLOUD_PWD>@<CLOUD_HOST>:5432/postgres" \
TARGET_DSN="postgres://postgres:<VPS_PWD>@<VPS_IP>:5432/postgres" \
bash scripts/migrate-to-self-hosted.sh
```

Dumps the `public` schema + `auth.users` from Cloud and restores into the
self-hosted DB. Self-hosted `auth`/`storage`/`realtime` schemas are left
untouched — only your app data moves.

> Lovable Cloud must be **resumed** while the dump runs. Resume it from
> Project Settings → Lovable Cloud, then start the migration.

---

## 3. Point the app at the VPS

Copy the three lines the installer prints into your app's `.env`:

```
VITE_SUPABASE_URL=http://<VPS_IP>:8000
VITE_SUPABASE_PUBLISHABLE_KEY=<ANON_KEY>
VITE_SUPABASE_PROJECT_ID=selfhosted
```

Redeploy / rebuild. Login, MCP, agent sessions, and pg_cron will now run
against your VPS and never pause.

---

## 4. Runtime agent (already on the same VPS)

`runtime/` connects to Postgres directly. Set on the VPS:

```
SUPABASE_URL=http://127.0.0.1:8000
SUPABASE_SERVICE_ROLE_KEY=<SERVICE_ROLE_KEY from CREDENTIALS.txt>
PG_DSN=postgres://postgres:<VPS_PWD>@127.0.0.1:5432/postgres
```

Then `cd runtime && npm install && npm run start`.

---

## 5. Housekeeping

- Back up nightly: `docker compose -f /opt/supabase/stack/docker-compose.yml exec -T db pg_dumpall -U postgres | gzip > /var/backups/supabase-$(date +%F).sql.gz`
- Update stack: `cd /opt/supabase/stack && docker compose pull && docker compose up -d`
- View logs: `docker compose logs -f kong auth rest db`

---

## Rollback

Everything lives under `/opt/supabase`. To remove:
`cd /opt/supabase/stack && docker compose down -v && rm -rf /opt/supabase`.
Point `.env` back at the old Cloud URL/key to return to Lovable Cloud.
