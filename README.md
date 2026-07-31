# CyberScope — AI-Powered VAPT Scanner

**CyberScope** is an autonomous, AI-driven Vulnerability Assessment and Penetration Testing (VAPT) platform. It combines automated reconnaissance, OWASP Top 10 scanning, deep audit analysis, CVE correlation, and intelligence feed ingestion into a single unified tool — with a built-in AI chatbox that can execute security operations on command.

## Option B — Long-Lived Agent Runtime (XBOW-style)

A Docker/VPS runtime under `runtime/` runs a persistent ReAct operator loop that
claims queued `agent_sessions` and drives real browser + HTTP + shell tools with
streaming logs into `agent_events`.

### Quick start (VPS)

```bash
cd runtime
cp .env.example .env    # set SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY,
                        # and one of LOVABLE_API_KEY / OPENAI_API_KEY / GEMINI_API_KEY
docker compose up -d --build
```

### Providers supported
- `lovable`  — Lovable AI Gateway (default, uses `LOVABLE_API_KEY`)
- `openai`   — `gpt-4o-mini` / `gpt-4.1-mini` via `OPENAI_API_KEY`
- `gemini`   — `gemini-2.5-flash` via native `@ai-sdk/google` and `GEMINI_API_KEY`

Pick the provider per target from the **Start Agent Scan** button on the Targets
page; live Plan / Act / Observe events stream into the Brain Panel.


---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [How It Works](#how-it-works)
3. [Edge Functions (Backend)](#edge-functions-backend)
4. [Request Flow](#request-flow)
5. [Modules & Features](#modules--features)
6. [Database Schema](#database-schema)
7. [AI Chatbox](#ai-chatbox)
8. [False Positive Elimination](#false-positive-elimination)
9. [Intel Feed Integration](#intel-feed-integration)
10. [Local Development](#local-development)
11. [Configuration](#configuration)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    React Frontend (Vite)                 │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────────┐ │
│  │ Targets  │ │ Findings │ │ Approvals│ │ AI Chatbox │ │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └─────┬──────┘ │
│       │             │            │              │        │
└───────┼─────────────┼────────────┼──────────────┼────────┘
        │             │            │              │
        ▼             ▼            ▼              ▼
┌─────────────────────────────────────────────────────────┐
│              Supabase Edge Functions (Deno)              │
│  ┌────────────┐ ┌─────────────┐ ┌──────────────────┐   │
│  │recon-engine│ │vuln-scanner │ │cyberscope-deep-  │   │
│  │            │ │             │ │audit             │   │
│  └────────────┘ └─────────────┘ └──────────────────┘   │
│  ┌────────────┐ ┌─────────────┐ ┌──────────────────┐   │
│  │intel-sync  │ │triage-brain │ │adaptive-validate │   │
│  └────────────┘ └─────────────┘ └──────────────────┘   │
│  ┌────────────┐ ┌─────────────┐ ┌──────────────────┐   │
│  │vapt-chat   │ │generate-poc │ │validate-finding  │   │
│  └────────────┘ └─────────────┘ └──────────────────┘   │
└─────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────┐
│                  Supabase PostgreSQL                     │
│  target_workspaces | discovered_endpoints | scan_logs   │
│  vulnerability_findings | pending_approvals             │
│  evidence_packages | suppression_vectors                │
│  intel_feeds | experience_vault | strategy_weights      │
│  chat_sessions | chat_messages | ai_provider_config     │
└─────────────────────────────────────────────────────────┘
```

---

## How It Works

### 1. Target Registration
A user adds a target (domain, IP range, or API schema URL) via the **Targets** page. This creates a `target_workspaces` record.

### 2. Reconnaissance
The **Recon Engine** (`recon-engine`) performs:
- DNS resolution and subdomain enumeration
- Technology fingerprinting (headers, meta tags, response patterns)
- Endpoint discovery and parameter extraction
- Results are stored in `discovered_endpoints`

### 3. OWASP Scanning
The **Vulnerability Scanner** (`vuln-scanner`) runs OWASP Top 10 checks:
- **A01 Broken Access Control**: IDOR, privilege escalation tests
- **A02 Cryptographic Failures**: SSL/TLS analysis, weak cipher detection
- **A03 Injection**: SQLi, XSS, SSTI, Command Injection with strict execution evidence
- **A05 Security Misconfiguration**: Header analysis, CORS, cookie flags
- **A07 Auth Failures**: Default credential checks, session analysis
- **A09 Logging Failures**: Security header presence validation
- **A10 SSRF**: Internal IP access tests

Each finding requires **execution proof** — not just heuristic deltas.

### 4. Deep Audit
The **Deep Audit** (`cyberscope-deep-audit`) performs advanced analysis:
- Uses `EXEC_DETECTORS` requiring explicit proof (SQL errors, XSS probe reflection, command output)
- Tests real parameters from discovered endpoints (not static fallbacks)
- Runs Intel Feed templates against the target
- Triple-verification: differential analysis (>30% body change), timing analysis (>3s delta), consistency checks (<3% variance)

### 5. AI Triage & Verification
The **Triage Brain** (`triage-brain`) AI-verifies each finding:
- Calculates confidence scores (0-100)
- Cross-references with suppression vectors
- Checks CVE applicability against detected tech stack
- Only high-confidence findings proceed to Approvals

### 6. Human Review
Verified findings appear in the **Approvals** queue where operators can:
- Approve → creates `vulnerability_findings` record
- Reject → optionally creates suppression vector for future FP prevention
- Escalate → flags for deeper manual analysis

---

## Edge Functions (Backend)

All backend logic runs as **Supabase Edge Functions** (Deno runtime). Here's each function:

| Function | Purpose | Trigger |
|---|---|---|
| `recon-engine` | Subdomain enum, tech fingerprint, endpoint discovery | POST with `targetId` |
| `vuln-scanner` | OWASP Top 10 active/passive scanning | POST with `targetId`, `scanType` |
| `cyberscope-deep-audit` | Deep vulnerability analysis with execution evidence | POST with `targetId` |
| `triage-brain` | AI-powered finding verification and scoring | POST with finding data |
| `adaptive-validate` | Multi-step adaptive validation with WAF bypass | POST with `approvalId` |
| `validate-finding` | Single finding validation with proof generation | POST with `findingId` |
| `generate-poc` | Generates PoC scripts (Python/curl) for findings | POST with `findingId` |
| `intel-sync` | Fetches security disclosures from HackerOne/GitHub | POST with `action: "sync"` |
| `deep-signal-triage` | Deep signal analysis for Intel Feed items | POST with `feedId` |
| `vapt-chat` | AI chatbox with tool-calling capabilities | POST with `message`, `sessionId` |

---

## Request Flow

### Example: OWASP Scan on a Target

```
Client (React)                  Edge Function                    Database
     │                              │                                │
     │  POST /vuln-scanner          │                                │
     │  {targetId, scanType}        │                                │
     │─────────────────────────────►│                                │
     │                              │  SELECT * FROM                 │
     │                              │  target_workspaces             │
     │                              │  WHERE id = targetId           │
     │                              │───────────────────────────────►│
     │                              │◄───────────────────────────────│
     │                              │                                │
     │                              │  SELECT * FROM                 │
     │                              │  discovered_endpoints          │
     │                              │───────────────────────────────►│
     │                              │◄───────────────────────────────│
     │                              │                                │
     │                              │  [Run OWASP checks]            │
     │                              │  - Injection tests             │
     │                              │  - Header analysis             │
     │                              │  - CVE correlation             │
     │                              │                                │
     │                              │  [Check suppression_vectors]   │
     │                              │  - Filter known FPs            │
     │                              │───────────────────────────────►│
     │                              │◄───────────────────────────────│
     │                              │                                │
     │                              │  INSERT INTO pending_approvals │
     │                              │  (verified findings only)      │
     │                              │───────────────────────────────►│
     │                              │                                │
     │                              │  INSERT INTO scan_logs         │
     │                              │───────────────────────────────►│
     │                              │                                │
     │  {success, vulnsFound,       │                                │
     │   approvalsQueued, ...}      │                                │
     │◄─────────────────────────────│                                │
```

### Example: AI Chatbox Tool Execution

```
Client                    vapt-chat                  Other Edge Functions
  │                           │                              │
  │  "Scan example.com"       │                              │
  │──────────────────────────►│                              │
  │                           │  [AI decides tool: run_recon]│
  │                           │                              │
  │                           │  POST /recon-engine          │
  │                           │  {targetId}                  │
  │                           │─────────────────────────────►│
  │                           │◄─────────────────────────────│
  │                           │                              │
  │                           │  [AI formats response]       │
  │                           │  [Saves to chat_messages]    │
  │                           │                              │
  │  "Found 15 endpoints..."  │                              │
  │◄──────────────────────────│                              │
```

---

## Modules & Features

### Command Center (`/`)
Dashboard with real-time stats: active targets, findings by severity, scan activity, system health.

### Targets (`/targets`)
Add/manage targets. Run Recon, OWASP Scan, and Deep Audit from a single interface. View discovered endpoints, scan stats, and audit results.

### Neural Log (`/logs`)
Real-time scan log viewer. Filter by log type (thought, action, result, error, info). Shows AI reasoning and decision traces.

### Findings (`/findings`)
All confirmed vulnerability findings with severity, confidence scores, AI verification status, and remediation guidance.

### Approvals (`/approvals`)
Human-in-the-loop review queue. Approve, reject, or escalate findings. Rejection can auto-create suppression vectors.

### False Positive Analytics (`/false-positives`)
Dashboard showing suppression vectors, FP rates per vulnerability class, and confidence score distributions.

### System Health (`/system-health`)
Monitor edge function performance, database health, and scanning infrastructure status.

### Intel Feed (`/intel-feed`)
Live security intelligence from HackerOne, GitHub, and CVE databases. Auto-generates test templates and cross-references with active targets.

### Settings (`/settings`)
Configure AI providers (Lovable AI, Google Gemini, OpenAI) with automatic fallback on credit exhaustion.

---

## Database Schema

### Core Tables
- **`target_workspaces`** — Registered scan targets (domain, IP, status)
- **`discovered_endpoints`** — URLs, methods, parameters found during recon
- **`vulnerability_findings`** — Confirmed vulnerabilities with evidence
- **`pending_approvals`** — Findings awaiting human review
- **`evidence_packages`** — Full HTTP req/res, PoC scripts, reports

### Intelligence Tables
- **`intel_feeds`** — Security disclosures with extracted payloads and templates
- **`intel_notifications`** — Alerts when intel matches active targets
- **`intel_sync_runs`** — Sync operation tracking

### Learning Tables
- **`suppression_vectors`** — False positive patterns for auto-filtering
- **`experience_vault`** — Payload effectiveness history for ML ranking
- **`strategy_weights`** — Per-tech-stack tool effectiveness tracking

### Operations Tables
- **`agent_tasks`** — Async task execution tracking
- **`scan_logs`** — Full scan operation logs with metadata
- **`chat_sessions`** / **`chat_messages`** — AI chatbox conversation history
- **`ai_provider_config`** — API keys for fallback AI providers

---

## AI Chatbox

The AI chatbox (`vapt-chat`) has **global admin access** to all edge functions. It can:

### Available Tools
| Tool | Description |
|---|---|
| `run_recon` | Execute reconnaissance on a target |
| `run_vuln_scan` | Run OWASP vulnerability scan |
| `run_deep_audit` | Execute deep audit with execution evidence |
| `get_findings` | Retrieve vulnerability findings |
| `get_approvals` | List pending approval items |
| `approve_finding` | Approve a pending finding |
| `reject_finding` | Reject finding + create suppression vector |
| `generate_poc` | Generate proof-of-concept script |
| `get_targets` | List all target workspaces |
| `sync_intel` | Trigger intel feed synchronization |
| `headless_dom_analysis` | Analyze DOM for dangerous sinks |
| `oob_listener` | Generate OOB callback payloads |
| `waf_fingerprint` | Identify WAF and suggest bypasses |
| `proxy_intercept` | Capture and audit HTTP traffic |
| `triage_finding` | AI-verify a specific finding |

### Chat History
All conversations are persisted in `chat_sessions` and `chat_messages` tables. Users can load previous sessions from the history panel.

---

## False Positive Elimination

CyberScope uses a **multi-layer FP elimination** strategy:

### Layer 1: Strict Execution Evidence
Every finding requires proof — not heuristic guesses:
- **SQLi**: Must produce SQL syntax errors or database-specific error messages
- **XSS**: Must reflect the exact `cyberscope` probe string in response
- **CMDi**: Must show command output (e.g., `uid=0`, `root:x:`)
- **SSTI**: Must return computed math results (e.g., `49` for `7*7`)

### Layer 2: Triple Verification
- **Differential Analysis**: >30% body change + status code deviation required
- **Timing Analysis**: >3 second response delta for time-based injection
- **Consistency Check**: <3% variance across 3 identical requests

### Layer 3: Suppression Vectors
Human-confirmed false positives create pattern-based filters that auto-suppress matching future findings. Patterns include request/response fingerprints and vuln class identifiers.

### Layer 4: AI Reverification
Findings pass through AI (Gemini/GPT) for CVE applicability checks against the target's actual tech stack. Mismatched CVEs are downgraded or suppressed.

### Layer 5: Experience Vault
Historical payload outcomes inform future scan strategies. Payloads that consistently produce FPs on specific tech stacks are deprioritized.

---

## Intel Feed Integration

### Ingestion Pipeline
1. **Fetch**: Pulls latest security disclosures from HackerOne and GitHub Advisory
2. **Parse**: Extracts vulnerability class, affected tech, payloads, and bypass techniques
3. **Template Generation**: AI generates executable test templates
4. **Target Matching**: Cross-references affected tech with active target tech stacks
5. **Auto-Testing**: Templates are automatically run against matched targets
6. **Tagging**: Feed items are tagged `confirmed` / `tested` with target-specific results

### Template Lifecycle
```
Disclosure → AI Parse → Template Generated → Matched to Targets → 
Executed → Result Tagged → Suppression Vector (if FP) OR Finding (if confirmed)
```

---

## Local Development

### Prerequisites
- **Node.js** 18+ and **Bun** (package manager)
- **Supabase CLI** (for edge function development)
- **Git**

### Setup

```bash
# Clone the repository
git clone <your-repo-url>
cd cyberscope

# Install dependencies
bun install

# Start the dev server
bun run dev
```

The app will be available at `http://localhost:5173`.

### Environment Variables
The following are auto-configured by Lovable Cloud:
- `VITE_SUPABASE_URL` — Backend API endpoint
- `VITE_SUPABASE_PUBLISHABLE_KEY` — Public API key
- `VITE_SUPABASE_PROJECT_ID` — Project identifier

### Edge Function Development

```bash
# Serve edge functions locally
supabase functions serve

# Deploy a specific function
supabase functions deploy vuln-scanner

# View function logs
supabase functions logs vuln-scanner
```

### Project Structure

```
├── src/
│   ├── components/        # React UI components
│   │   ├── ui/            # shadcn/ui primitives
│   │   ├── AppSidebar.tsx # Navigation sidebar
│   │   ├── Layout.tsx     # App shell layout
│   │   └── VaptChatbox.tsx# AI chatbox component
│   ├── pages/             # Route pages
│   │   ├── Index.tsx      # Command Center dashboard
│   │   ├── Targets.tsx    # Target management + scanning
│   │   ├── Findings.tsx   # Confirmed vulnerabilities
│   │   ├── Approvals.tsx  # Human review queue
│   │   ├── FalsePositives.tsx # FP analytics dashboard
│   │   ├── NeuralLog.tsx  # Scan log viewer
│   │   ├── IntelFeed.tsx  # Intelligence feed
│   │   ├── SystemHealth.tsx # Infrastructure monitoring
│   │   └── Settings.tsx   # AI provider configuration
│   ├── services/          # Client-side service logic
│   │   ├── LearningService.ts    # FP suppression management
│   │   ├── TriageBrain.ts        # Finding triage logic
│   │   ├── AdaptiveRunner.ts     # Adaptive validation
│   │   ├── IntelScraper.ts       # Intel feed processing
│   │   └── ...                   # 20+ specialized services
│   └── integrations/
│       └── supabase/      # Auto-generated client & types
├── supabase/
│   ├── functions/         # Edge functions (Deno)
│   │   ├── recon-engine/
│   │   ├── vuln-scanner/
│   │   ├── cyberscope-deep-audit/
│   │   ├── vapt-chat/
│   │   └── ...
│   └── migrations/        # Database migrations
└── public/                # Static assets
```

---

## Configuration

### AI Provider Priority
CyberScope uses a cascading AI provider system:

1. **Lovable AI** (default, no API key needed)
2. **Google Gemini** (fallback on 402/429)
3. **OpenAI GPT** (secondary fallback)

Configure API keys in **Settings** → **AI Providers**.

### Scanning Configuration
Scans are configured per-target with these options:
- **Scan Type**: `owasp_top10` | `deep_audit` | `full`
- **Scope**: Domain, subdomains, specific endpoints
- **Aggressiveness**: Controls payload intensity and timing

---

## Security Notes

- All tables have Row-Level Security (RLS) enabled
- Edge functions validate input and sanitize payloads
- API keys are stored encrypted in the database
- The AI chatbox operates with admin-level access — restrict access in production
- Suppression vectors prevent scan result manipulation by requiring human confirmation

---

## License

Private / Internal Tool

---

*Built with [Lovable](https://lovable.dev) • Powered by Supabase Edge Functions*

---

## 🔐 Auth, Roles & Scan Credits

CyberScope now ships with built-in authentication and a credit system:

- **Sign in** at `/auth` (email/password or Google).
- Every new user gets **3 free target scans**. Each `Recon`, `OWASP Vuln-Scan`, or `Deep Audit` consumes **1 credit**.
- **Admins** have **unlimited** scans and an `/admin` panel to grant credits to users or promote other users to admin.
- Bootstrapping the first admin: open the backend SQL editor and run
  `insert into public.user_roles(user_id, role) values ('<your-auth-uid>', 'admin');`

## 🗄️ External Database (BYO Postgres)

If you want to keep a local/private copy of all findings, plug in any Postgres URL in **Settings → External Database**:

```
postgres://user:password@host:5432/dbname
```

Click **Test & Init Schema** — the `cyberscope_findings` table is created automatically. Compatible with Neon, RDS, self-hosted Supabase, or local Docker:

```bash
docker run -d --name cyberscope-db -e POSTGRES_PASSWORD=secret -p 5432:5432 postgres:16
# then use: postgres://postgres:secret@host.docker.internal:5432/postgres
```

Use the edge function `external-db-mirror` with `{ action: "mirror", userId }` to push findings into your DB on demand.

## 📄 VAPT PDF Reports

From **Findings** click **PDF** on any row to download a per-finding professional report (PoC, affected endpoint, remediation, CVSS, AI triage). Click **Export Report** to download a full multi-finding VAPT bundle.

## New Modules (v1.2)

- **Bug Bounty Submission** — Findings page → "Submit" button. Add HackerOne username + API token and/or Bugcrowd token in Settings → Bug Bounty. If tokens are missing, submission falls back to a perfectly formatted Markdown export you can paste manually.
- **Sandboxed Exploit Worker** — Findings page → "Sandbox" button. Tries your Docker worker first (`POST /sandbox`) and falls back to the edge sandbox automatically. Configure the worker in Settings → External Infrastructure.
- **DOM-Fuzz (Playwright)** — Auto-dispatched on every full scan. Uses worker `POST /playwright` if available, else falls back to the edge headless-browser DOM watcher.
- **Application Package Scanner** — New "App Packages" page in the sidebar. Upload `.apk / .exe / .ipa / .zip / .jar`, AI audits manifests, source files, secrets, and configuration.
- **Extended Docker Worker** — `docker-worker-reference/` now ships with `apktool`, `jadx`, and Playwright/Chromium so all the new endpoints work end-to-end.

---

## Latest updates (July 2026)

### System Health — live scan control
- Per-target progress bars (queued/running/done/failed with %) at `/system-health`.
- **Cancel per-job** and **Cancel all pending for target** to free AI credits.
- Live job queue auto-refreshes every 5s.
- **Purge All History** (RPC `purge_history`) resets a target or every table safely.

### OWASP Checklist
- Full dependency chain shown for every missing A01–A10 check (checklist → scanner module → job type → last run).
- **Auto-rerun missing** / **Run now** buttons call `enqueue_missing_owasp_modules` (respects active-scan guard, `_force=true` overrides).
- **Delete checklist** with typed confirmation (`DELETE <name>` / `DELETE <domain>` / `DELETE <uuid>`); all deletions written to `owasp_checklist_audit`.
- Orphaned checklists (target row deleted) can now be removed by UUID.

### Findings provenance
- New **Provenance** tab in the finding details dialog: scanner/source, vuln class, timestamps, affected URL, and the `dedup_key` / `group_key` used to collapse duplicates across retries and agent restarts.
- DB trigger `trg_auto_dedup_finding` auto-generates canonical keys for every scanner (host + normalized path + param + vuln class), so retries cannot create duplicates.

### NVD sync
- `nvd-intel-sync` now cross-references CVEs against **queued / running / in_progress / completed** targets (not just completed).
- Dedupes per-target CVE jobs so the hourly cron cannot re-queue the same `cveId` while a job is still queued or running.

### Subdomain enumeration
- `subdomain-enum` fans out to **crt.sh + HackerTarget + AlienVault OTX + Wayback CDX** in parallel plus the 63-word brute list, typically 3–5× more hosts before fuzzing.

### Verification & audit commands
```sh
# Duplicate audit
psql -c "SELECT dedup_key, count(*) c FROM vulnerability_findings GROUP BY dedup_key HAVING count(*)>1 ORDER BY c DESC;"
psql -c "SELECT group_key,  count(*) c FROM vulnerability_findings GROUP BY group_key  HAVING count(*)>1 ORDER BY c DESC;"

# Trigger NVD sync
curl -s -X POST "$SUPABASE_URL/functions/v1/nvd-intel-sync" \
     -H "Authorization: Bearer $SUPABASE_ANON_KEY" \
     -H "Content-Type: application/json" \
     -d '{"daysBack":3}'
```
