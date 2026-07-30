# CyberScope Agent Runtime (Option B)

Long-lived VAPT agent. One process per target. Reasoning loop lives here, tools call real HTTP + Playwright + shell. All state (sessions, events, findings) lives in Supabase.

## Deploy to your VPS

```bash
# 1. Clone the repo onto your VPS
git clone <this-repo> /opt/cyberscope
cd /opt/cyberscope/runtime

# 2. Create .env (see .env.example)
cp .env.example .env
nano .env   # fill in the 4 keys

# 3. Build & run with Docker Compose
docker compose up -d --build

# 4. Watch logs
docker compose logs -f agent
```

The container polls `agent_sessions` for `status='queued'` rows, claims them atomically via `claim_agent_session()`, and runs the operator loop until `finish` or budget exhaustion. Streams every step into `agent_events` — BrainPanel renders it live via Supabase Realtime.

## Required env vars

| Name | Where to get it |
| --- | --- |
| `SUPABASE_URL` | Lovable → Project Settings |
| `SUPABASE_SERVICE_ROLE_KEY` | Same page (the secret one) |
| `LOVABLE_API_KEY` | Auto-provisioned; copy from project secrets |
| `OPENAI_API_KEY` | Optional; enables provider=openai |
| `GEMINI_API_KEY` | Optional; enables provider=gemini directly |

## How the app talks to it

The user clicks **Start Agent Scan** in the Lovable UI → `agent-start` edge function inserts a row in `agent_sessions` with `status='queued'`. Your VPS worker picks it up within ~3s.

No inbound ports needed — the worker only makes outbound HTTPS to Supabase.

## Scaling

Every extra container = one more concurrent target. `claim_agent_session()` uses `FOR UPDATE SKIP LOCKED`, so N workers never race. Set `docker compose up -d --scale agent=5` for 5 parallel targets.
