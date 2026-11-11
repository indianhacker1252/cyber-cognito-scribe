# CyberScope — Architecture Decisions

- **Runtime DB access goes through `runtime-gateway`, never the service role key.** Lovable Cloud never exposes the service role key, so the VPS runtime authenticates to the `runtime-gateway` edge function with a shared `RUNTIME_SECRET` (x-runtime-secret header); the gateway executes a whitelisted set of table ops + RPCs (`claim_agent_session`, `merge_world_model`) with the service role. `runtime/src/db.ts` is a supabase-js-style chain builder over that gateway — keep new runtime table access inside the gateway's whitelist.
- **Edge functions always return 200 OK** (errors in JSON body) and use `safeFetch` with 4–8s timeouts; hard 50s execution limit.
- **Findings require proof**: XSS needs headless-browser proof; HIGH/CRITICAL findings require human approval before active verification.
- **Preserve workload-tier model selection and provider fallback routing during model maintenance.** Migrate only catalog-confirmed deprecated Gateway selections; keep direct-provider choices separate to avoid changing unrelated request contracts.
- **Runtime is a long-lived daemon** (runtime/, Docker), one process per target, claiming `agent_sessions` rows via `FOR UPDATE SKIP LOCKED`; edge functions stay for short jobs.
- **Runtime Lovable AI uses the shared-secret runtime-gateway streaming proxy**, never a managed AI key on the VPS; restore upstream errors at the SDK boundary so rejected requests cannot appear as completed scans.
