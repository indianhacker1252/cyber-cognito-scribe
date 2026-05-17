# Enterprise Launch Hardening — XBOW-Class Coverage

Goal: Make the scanner cover the full OWASP Top 10 actively (not just label them), crawl every JS/asset file for hidden secrets and code bugs, and remove the per-run caps that are stopping deep discovery.

## Current state (audit)

`vuln-scanner` already maps to all 10 OWASP categories but the active probing is throttled by the 60s edge-function ceiling. Real limiters today:
- `slice(0, 6)` on vuln classes per run, `slice(0, 3)` on endpoints per class, `slice(0, 12)` on payloads per param, `MAX_ADAPTIVE_RETRIES = 3`, `MAX_SCAN_MS = 55000`.
- No active probes for: A04 Insecure Design (business-logic), A07 weak-password / credential-stuffing, A08 subresource-integrity / unsigned-update, A09 logging-pipeline checks, A10 SSRF blind-OOB.
- No JS-asset crawler: no scan of `*.js` / `*.map` / `*.json` / `.env*` / HTML inline scripts for API keys, JWTs, AWS/GCP creds, internal hostnames, debug routes, hardcoded admin paths.
- No source-code bug scanner against discovered front-end bundles (eval, postMessage `*`, `dangerouslySetInnerHTML`, `Function()`, prototype-pollution sinks, weak crypto).

## Deliverables

### 1. New edge function: `secrets-and-source-scan`
Crawls every JS / JSON / source-map / HTML / `.env*` / `robots.txt` / `sitemap.xml` reachable from `discovered_endpoints`. For each file:
- Regex bank for ~80 secret types (AWS, GCP, Azure, Stripe, Slack, GitHub, JWT, Twilio, SendGrid, OpenAI, private keys, DB URIs, internal IPs, S3 buckets, Firebase configs, Mapbox, Algolia, Sentry DSN, etc.).
- Source-map (`.js.map`) auto-fetch + reconstruct original sources, then taint-scan with the same SAST patterns used by `mythos-codebase-ingest` (sources → sinks).
- Front-end bug detectors: `eval(`, `new Function(`, `dangerouslySetInnerHTML`, `innerHTML=`, `document.write`, `postMessage(.., '*')`, prototype-pollution sinks, weak crypto (`Math.random` for tokens, `MD5`, `SHA1`), `localStorage`/`sessionStorage` for tokens, hardcoded admin endpoints, debug routes, GraphQL introspection URLs.
- Findings written to `vulnerability_findings` with full file path, line number, evidence snippet, OWASP category (A02 / A03 / A05 / A08).

### 2. `vuln-scanner` deep mode
- Add `deep: true` request flag. When set, the function enqueues a `scan_jobs` row instead of running inline, and the existing `scan-job-worker` processes it without the 50s budget — iterating until every endpoint × every vuln class × full payload corpus is exhausted.
- Inline (fast) mode keeps current caps for the live-UI run, but `slice(0, 6)` → `slice(0, 12)`, payloads `slice(0, 12)` → `slice(0, 24)`, `MAX_ADAPTIVE_RETRIES` 3 → 6.
- Add active probes for the missing OWASP slices:
  - **A04 Insecure Design**: race-condition probe on state-changing endpoints (already have `race-runner`, wire it in), price/qty tampering on numeric params.
  - **A07 Auth Failures**: rate-limit detector (50 fast logins → expect 429), default-cred dictionary against discovered login forms.
  - **A08 Integrity**: check for `<script src="…">` without SRI, unsigned package endpoints.
  - **A09 Logging**: hit `/admin`, `/debug`, `/.git/HEAD`, `/actuator/*`, `/api/swagger*` and flag if reachable.
  - **A10 SSRF blind**: wire `oob-collector` token into any URL-shaped parameter and watch `oob_callbacks` for a hit.

### 3. `recon-engine` deeper crawl
- Lift `maxEndpoints: 8` cap. New defaults: 40 endpoints, recursive depth 3, follow all same-origin links plus subdomains.
- Parse every linked JS/CSS/JSON, extract URLs from string literals (already partially done), add discovered routes back to `discovered_endpoints`.
- Auto-trigger `secrets-and-source-scan` at the end of recon.

### 4. Orchestrator wiring
- `mythos-orchestrator` gains a `phase: "deep-asset-scan"` that calls `secrets-and-source-scan` between `recon` and `vuln-scanner`.
- Findings from the asset scan feed the same Mythos confidence/triage pipeline, get reported the same way to bounty platforms.

### 5. UI surface
- `Findings.tsx` filter chip for `source = secrets-scanner`.
- `NeuralLog.tsx` shows per-file progress (`🔑 Scanning app.bundle.js — 0 secrets, 3 sinks`).

## Out of scope for this pass
- Mobile binary scanning (already in `app-package-scan`).
- Authenticated multi-step business-logic chains beyond race + IDOR (Mythos handles those).
- Container/CI-CD scanning.

## Technical notes
- `secrets-and-source-scan` will use the worker pattern from day one (no 60s ceiling) — request enqueues a `scan_jobs` row, worker iterates with 8s timeout per fetch via the shared `safeFetch`.
- All new findings: `confidence_score` derived from regex specificity (e.g. AWS AKIA prefix + 40-char secret = 95, generic 32-hex = 40).
- HIGH/CRITICAL findings (live keys, RCE patterns) auto-create `pending_approvals` rows per existing HITL policy.

## Confirm before I build
1. OK to enqueue deep scans as background jobs (results appear over minutes, not seconds)?
2. OK to auto-fetch `.js.map` files when present (they're public assets but some hunters consider it noisy)?
3. Keep default-credentials check ON for A07 (uses tiny ~20-pair list, non-destructive)?
