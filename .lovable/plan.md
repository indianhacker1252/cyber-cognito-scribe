# Neural Log evidence — what is actually broken

Pulled the last 24h of `scan_logs` directly. The numbers tell the whole story:

| Count | Message |
|---|---|
| 1 | `[AI] AI credits exhausted` |
| 73 × 2 | `🥷 Agent A/B: [A] LLM error 402` |
| 73 × 5 | `🧬 Mutation #1..#5 rejected (class=bllmerror)` |
| 70+ | `⚔️ Executed: [B] LLM error 402 → 200/403/301 …` |
| 3 | `🧐 Verdict: false_positive — status=403→403` |

So the chain is:

1. Lovable AI gateway returns **HTTP 402 (credits exhausted)** once.
2. `_shared/llm.ts` does not detect "credits exhausted" as terminal — it surfaces the raw error string `"[B] LLM error 402"` to the caller.
3. **Coordinator (`Agent A/B`) treats that error string as the next payload** and ships it to the target (`Executed: [B] LLM error 402 → 200`).
4. `EvolutionaryFuzzer` correctly classifies the response as `bllmerror` and rejects mutations #1–#5 — but the scan keeps looping, producing **365 garbage mutations and ~70 garbage HTTP requests** for a single scan.
5. Every advanced module (mutator, debate, variant-gen) eats the same 402 → entire scan returns 0 findings + a wall of noise.

**This is the single root cause of "tool not working".** WAF tuning, mutator, kill-chain etc. are downstream of a dead AI gateway.

---

# Phase 1 — Stop the bleed (Neural Log cleanup)

Six surgical fixes, no schema changes:

### 1. Hard-fail on credit exhaustion (`_shared/llm.ts`)
Detect 402 + body containing `credits|exhausted|insufficient` → throw a **typed** `AiCreditsExhaustedError`, do **not** fall through to next attempt, do **not** return error string as `text`.
After 1 hit, set a module-level cooldown flag for 5 min so siblings short-circuit instantly.

### 2. Callers must check `ok` before using `text` (audit the 8 leaky callers)
`Coordinator.ts`, `EvolutionaryFuzzer.ts`, `mythos-debate`, `mythos-variant-gen`, `mythos-chainer`, `exploit-engine`, `request-mutator`, `vapt-chat`.
Currently they all do `const out = await llmCall(); use(out.text)`. Fix: `if (!out.ok || out.error) { logSkip(); return; }`.

### 3. Refuse to ship LLM-error strings as payloads (`Coordinator.ts`, `EvolutionaryFuzzer.ts`)
Sanitiser before `fetch`: if `payload.startsWith('[A]'|'[B]'|'LLM error'|'bllmerror'|'AI credits')` → drop, log `mutation_skipped_invalid_payload`.

### 4. Bubble a single user-visible banner instead of 365 log lines
When `AiCreditsExhaustedError` fires, write **one** `scan_logs` row `log_type='error'` (need to add `error` to `log_type` enum — migration) and pause the scan with status `awaiting_credits`. Neural Log UI already renders error rows distinctively.

### 5. Pause/resume the scan instead of looping
`scan-job-worker` checks `awaiting_credits` flag each tick → sleeps the job, no further LLM calls, exits cleanly. Resume button in `SystemHealth.tsx` clears the flag.

### 6. Provider fallback ordering when 402
On Lovable 402 → try Gemini direct (if `GEMINI_API_KEY`) → OpenAI → Anthropic. Only set `awaiting_credits` when **all** providers return throttle/no-key. Currently fallback fires but each provider also returns 402 because we re-use the same prompt without resetting state — fix the iterator.

**Verification for Phase 1:**
- Trigger scan with empty Lovable balance → Neural Log shows **1** red error row, **0** `Executed: [B] LLM error 402` rows, **0** `Mutation rejected (bllmerror)` rows.
- `select count(*) from scan_logs where message ilike '%bllm%' or message ilike '%LLM error 402%'` → 0 for new scans.

---

# Phase 2 — Beyond XBOW

Once the AI gateway can't poison the scan, layer in capabilities XBOW does not have publicly:

### A. Multi-agent **adversarial dialogue** with a "Skeptic" persona
- Agent A (Attacker) proposes payload → Agent S (Skeptic) tries to **falsify** the bug class before execution (cheaper than running it).
- Only payloads that survive Skeptic are fired. Cuts LLM spend ~40% and kills the bllmerror-as-payload class.

### B. **Differential semantic-graph diffing** (not status-code/length diff)
- Parse baseline + mutated response into a DOM/JSON tree → compute *structural* delta (added auth-bearing fields, new ID enumeration, exposed PII tokens).
- Promotes "200 → 200 but body now contains other users' data" cases that status-code diff misses.

### C. **Behavioural canary tokens** for blind / out-of-band bugs
- Inject unique HMAC tokens into headers, params, JSON bodies, JWT claims.
- New `oob-collector` already exists — wire it into every fuzz family (SSRF, blind XSS, log4shell-style, template-injection).
- A token landing in `oob_callbacks` table = **deterministic proof** with zero false positives.

### D. **Self-rewriting payload genome** (genetic algorithm with fitness = real-target reward)
- Keep a per-target `payload_genome` table: payload → reward (status delta, length delta, oob hit, time delta).
- Each generation: top-K survive, crossover + Skeptic-filtered LLM mutation. After 5 gens, payloads are target-specific (XBOW uses generic LLM only).

### E. **Auto chain-execution** with rollback proof
- `kill-chain-graph` already exists. Add: when a chain reaches `Critical Impact` and every edge has `proof_tier='verified'`, auto-run a **read-only** end-to-end PoC in `sandbox-exec`, capture HAR + screenshot + curl reproduction, attach to evidence package, route to HITL.

### F. **Tech-stack memory** so the same finding class isn't rediscovered every scan
- New `target_brain` jsonb on `target_workspaces`: WAF profile, working bypass families, confirmed framework quirks, payloads that worked.
- Next scan starts at gen-5 fitness, not gen-0.

### G. **Live regression watch** (post-scan)
- `canary-drift-monitor` already exists. Tighten: every confirmed finding gets a daily re-fire with the *exact* captured `request_raw`. If it still works → email + Slack via `bb-submit` style hook, regression badge in `Findings.tsx`.

---

# Technical scope

**Edge functions to patch:**
- `_shared/llm.ts` — typed `AiCreditsExhaustedError`, cooldown flag, fixed fallback iterator
- `Coordinator.ts`, `EvolutionaryFuzzer.ts` — payload sanitiser + `ok`/`error` checks
- `mythos-debate`, `mythos-variant-gen`, `mythos-chainer`, `exploit-engine`, `request-mutator`, `vapt-chat` — same
- `scan-job-worker` — honour `awaiting_credits`, exit cleanly

**New edge functions (Phase 2):**
- `skeptic-agent` (Phase 2A)
- `semantic-graph-diff` (Phase 2B)
- `payload-genome` (Phase 2D)

**Frontend:**
- `NeuralLog.tsx` — render `log_type='error'` rows in red with a "Resume scan" button when status=`awaiting_credits`
- `SystemHealth.tsx` — AI credit gauge, manual resume

**Migrations:**
- `ALTER TYPE log_type ADD VALUE 'error'`
- `scan_jobs.status` allow `awaiting_credits`
- `payload_genome` table (target_id, payload, fitness, generation, parents jsonb) + grants + RLS
- `target_workspaces.target_brain jsonb default '{}'::jsonb`

# Out of scope
- Replacing Lovable AI
- Buying more credits (Phase 1 must work even at 0 credits — uses external provider fallback or pauses cleanly)
- Mobile / native binary fuzzing

# Confirm before I build

1. **Pause vs. silent fallback**: when Lovable credits hit 0, do you want the scan to **pause** with a Resume button (recommended), or **continue** silently on Gemini/OpenAI if those keys exist?
2. **Skeptic agent cost**: it adds ~1 extra LLM call per proposed payload (≈+20% spend). OK, or only enable for HIGH/CRITICAL classes?
3. **OK to add `error` value to the `log_type` enum** (small migration, lets us paint Neural Log rows red)?
