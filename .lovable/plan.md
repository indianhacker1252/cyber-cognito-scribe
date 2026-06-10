# Why the last scan failed — evidence from the code

I traced your three complaints to concrete gaps in the deployed functions:

1. **Dropped findings (Recon + ParamBrute):**
   - `supabase/functions/recon-engine/index.ts` — zero references to `vulnerability_findings`. Leaked secrets (Google API keys, JWTs, .env) are logged into `scan_logs` only.
   - `supabase/functions/param-bruteforce-xss/index.ts` — comment at line 5 says "the xss-reflection-promoter then auto-promotes". The promoter only runs if the reflection row exists with the exact shape it expects. If promotion fails, the 6 confirmed XSS sinks never reach `vulnerability_findings` → never reach `owasp_coverage` → never appear in the report matrix.

2. **`bllmerror` mass-crash:**
   - `supabase/functions/_shared/llm.ts` catches only HTTP 402/429. There is **no concurrency limiter** anywhere. `EvolutionaryFuzzer`, `exploit-engine`, `vuln-scanner` and `mythos-*` all call `llmCall` in parallel `Promise.all` loops, so a single target can fan out 30–50 simultaneous Lovable AI calls. Gateway returns a non-HTTP `bllmerror` string which is not in the retry whitelist → caller treats it as fatal.

3. **WAF 403 wall:**
   - `EvolutionaryFuzzer.ts` and `exploit-engine` re-issue the same mutation family after a 403. The LLM prompt does not include the previous response status, so the model never learns the target is WAF-protected and keeps emitting `<script>alert(1)</script>`-class payloads.

4. **No request/response evidence in findings** — `vulnerability_findings.evidence` only stores `payload` + `status`. The full request line, headers, and response body diff are discarded, so PoCs aren't reproducible from the UI.

5. **"Basic VAPT only"** — `mythos-orchestrator` does call the new advanced modules but **only after** the main scan completes, and it does not pass discovered params/auth state into them. They re-discover from scratch and time out.

---

# Plan — what to build

## Part A — Stop losing findings (the root cause of "scan looks empty")

### A1. Central writer module `_shared/findings-writer.ts`
Single helper `recordFinding({targetId, scanLogId, category, severity, evidence, request, response, source})` that:
- Inserts into `vulnerability_findings` with full request/response captured
- Upserts the matching `owasp_coverage` row (so the matrix always reflects reality)
- Inserts the request/response into `request_replays` for the Findings UI "Repeat" button
- Returns the finding id so the caller can chain it into `attack_graph_nodes`

### A2. Wire it into the leaky modules
- `recon-engine`: every `secret_found` hit (Google key, AWS key, JWT, .env, private key regex) → `recordFinding({category:'sensitive-data-exposure', severity:'high'})`.
- `param-bruteforce-xss`: when reflection probe returns canary intact AND browser-verify confirms execution, write directly via `recordFinding` instead of relying on the promoter. Keep promoter as fallback.
- `differential-oracle`, `symbolic-param-explorer`, `business-logic-fuzzer`, `auth-confusion-suite`, `prototype-pollution-gadgets`, `desync-smuggling-v2`, `ai-surface-attacker`: each currently logs to console — switch to `recordFinding`.

## Part B — Kill the `bllmerror` storm

### B1. Concurrency-limited LLM gateway
Patch `_shared/llm.ts`:
- Add a module-level async semaphore (size 5) that gates every `llmCall`.
- Catch `bllmerror`, `rate_limit`, `quota`, HTTP 402/429/503 → exponential backoff (1s, 2s, 4s, 8s) before falling through to next provider.
- New `llmCallBatch(messages[], {concurrency:5})` helper so callers stop using `Promise.all`.

### B2. Refactor heavy callers
- `EvolutionaryFuzzer`, `exploit-engine`, `mythos-chainer`, `mythos-debate`, `mythos-variant-gen` — replace `Promise.all(payloads.map(llmCall))` with `llmCallBatch`.

## Part C — Adaptive WAF evasion

### C1. WAF gate inside the mutation loop
`_shared/waf-detect.ts` already fingerprints (Cloudflare/Akamai/AWS WAF). Extend with:
- `WafFeedback.observe(prevStatus, newStatus, prevLen, newLen)` → returns a tier: `none | soft-block | hard-403 | challenge-page`.
- When tier ≠ `none`, the next LLM prompt receives a forced suffix:
  > "WAF DETECTED (vendor=X, tier=Y). Last payload returned 403. For the next payload you MUST use one of: HTML-entity encoding, Unicode escape, JS template literals, SVG event handlers, double-URL-encoding, comment splitting, or case-mixed keywords. Do NOT repeat `<script>` / `onerror=` literally."
- After 2 consecutive WAF blocks, switch the fuzzer to the SecLists WAF-bypass corpus (`SecListsLoader.loadWafBypass()`) for the next 10 payloads before resuming LLM.

### C2. Per-target WAF profile
Persist detected vendor + working bypass families in `target_workspaces.waf_profile` (jsonb). Subsequent scans start from the known-good bypass set.

## Part D — Request/Response capture + replay

### D1. Schema additions (`vulnerability_findings`)
- `request_raw` text — full HTTP request line + headers + body
- `response_raw` text — status, headers, body (≤32 KB)
- `response_diff` jsonb — semantic diff vs baseline (length delta, new tokens, removed tokens, status change)

### D2. Auto-mutation from captured traffic
New `request-mutator` edge function:
- Reads any `request_replays` row, generates 8 mutations (param tamper, type-juggle, verb-swap, header-injection, content-type swap, prototype-pollution param, ID enum, JWT alg swap).
- Fires each through `request-repeater`, calls `semantic-diff` against the baseline, and feeds confirmed anomalies into `recordFinding` and the kill-chain graph.
- Runs automatically after every successful finding (chain reaction = more confirmed bugs from one seed).

## Part E — Make the advanced modules actually run with context

### E1. Orchestrator wiring (`mythos-orchestrator`)
Two changes:
- Move `advanced-modules` phase to run **in parallel** with `vuln-scanner` (not after), but only after `recon` + `auth-deep` so they receive discovered endpoints, params, session jars, and auth profiles.
- Pass a shared `ScanContext` blob (endpoints, params, cookies, JWTs, tech-stack fingerprint) to every advanced module so they don't re-discover.

### E2. OWASP coverage fairness
- `template-runner` already does a "fairness pass" — extend it so every OWASP-2021 category (A01–A10) gets at least N=3 active probes per target, even if earlier modules reported nothing. Currently A04 (Insecure Design) and A08 (Software & Data Integrity) silently skip on most targets.

### E3. Kill-chain auto-execution
After every new finding lands, enqueue a `kill-chain-graph` job. When the graph produces a chain with `cost < threshold` AND every edge has `proof_tier='verified'+`, auto-fire `exploit-chain-runner`, capture HAR + screenshot, write the evidence_package, and submit for HITL approval.

## Part F — UI surfacing

### F1. `Findings.tsx`
- New "Request" / "Response" tabs in the finding details dialog rendering `request_raw` / `response_raw` with syntax highlighting.
- "Re-run mutations" button → fires `request-mutator` for this finding.
- New badge `source=recon-secret` and `source=param-brute-xss` so the dropped categories are visible.

### F2. `OwaspCoverage.tsx`
- Show fairness-pass status per category (probes_attempted / probes_required) so the user sees A04/A08 actually being tested.

---

# Technical details

**New / changed files:**

Edge functions:
- `_shared/findings-writer.ts` (new) — central recordFinding helper
- `_shared/llm.ts` (patch) — semaphore(5), bllmerror catch, exp-backoff
- `_shared/waf-detect.ts` (extend) — WafFeedback tier + prompt suffix
- `recon-engine/index.ts` (patch) — call recordFinding on secrets
- `param-bruteforce-xss/index.ts` (patch) — call recordFinding on confirmed sinks
- `differential-oracle`, `symbolic-param-explorer`, `business-logic-fuzzer`, `auth-confusion-suite`, `prototype-pollution-gadgets`, `desync-smuggling-v2`, `ai-surface-attacker` — switch console logs to recordFinding
- `request-mutator/index.ts` (new) — auto-mutate every confirmed finding
- `template-runner/index.ts` (patch) — strict OWASP A01–A10 fairness ≥3 probes
- `mythos-orchestrator/index.ts` (patch) — parallel advanced phase + ScanContext
- `exploit-engine`, `EvolutionaryFuzzer`, `mythos-chainer`, `mythos-debate`, `mythos-variant-gen` — switch to `llmCallBatch`

Frontend:
- `src/services/EvolutionaryFuzzer.ts` (patch) — concurrency limit + WAF feedback wiring
- `src/pages/Findings.tsx` (patch) — Request/Response tabs, Re-run mutations
- `src/components/FindingDetailsDialog.tsx` (patch) — raw request/response panes
- `src/pages/OwaspCoverage.tsx` (patch) — fairness-pass progress

Migration:
- `vulnerability_findings`: add `request_raw text`, `response_raw text`, `response_diff jsonb`, `source text`
- `target_workspaces`: add `waf_profile jsonb default '{}'`
- index on `vulnerability_findings(target_id, source, created_at desc)`

**Verification:**
1. Trigger a scan on a WAF-protected target → check `_shared/llm.ts` logs show "semaphore wait" messages and 0 `bllmerror` crashes.
2. After scan: `select source, count(*) from vulnerability_findings group by source` must show `recon-secret`, `param-brute-xss`, `differential-oracle`, etc.
3. Findings UI: open any finding → Request and Response tabs populated; "Re-run mutations" produces ≥1 new finding for at least 20% of seeds.
4. OWASP page: all 10 categories show ≥3 probes attempted.

# Out of scope (this pass)
- Replacing Lovable AI with a self-hosted model
- Multi-hour persistent worker (would need the Docker worker path)
- Mobile / binary chains

# Confirm before I build
1. OK to add `request_raw` / `response_raw` columns (cap 32 KB each, can grow DB size on big scans)?
2. Semaphore size 5 OK, or do you want 3 (safer) / 10 (faster)?
3. Should `request-mutator` auto-fire on every confirmed finding, or only on HIGH/CRITICAL to control LLM spend?
