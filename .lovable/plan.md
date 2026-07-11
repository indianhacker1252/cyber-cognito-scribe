# Deep Audit — What Actually Broke

I queried the live database. The failures have **4 concrete causes**, not 17.

## Evidence (from your DB, last 6h)


| Symptom                                                                                                          | Real cause                                                                                                                                                                                                                |
| ---------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `subdomain_enum` ran **171×**, `juicy` **171×**, `js_deep` **171×**, `mythos_step` **134×** for the same targets | `scan_jobs.idempotency_key` column exists and has a unique index — **but no enqueue code sets it**. The dedup index is a no-op.                                                                                           |
| Every AI-dependent module returns "AI credits exhausted"                                                         | Lovable AI genuinely returned 402. Fallback chain in `_shared/llm.ts` reads `ai_provider_config` table — **table is empty / `enabled=false**`, so nothing falls back. User has no OpenAI/Gemini/Anthropic key configured. |
| Only 2 findings in 24h (both from `template-runner`)                                                             | Every real detector short-circuits on AI 402 OR loops without ever producing evidence.                                                                                                                                    |
| Loop-guard "installed" but subdomain/js_deep/vuln_scan still loop                                                | Last pass only added loop-guard to 5 modules. The looping ones (`subdomain-enum`, `js-deep-expand`, `recon-engine`, `vuln-scanner`, `mythos-agent`) were never wired.                                                     |
| `phase-arbiter` re-enqueues same modules                                                                         | It reads `expected_modules` but has no "already scheduled in last N minutes" check before inserting jobs.                                                                                                                 |


## Fix plan (surgical, no new features)

### 1. Make idempotency_key actually work (kills 90% of loops)

- Central helper `_shared/enqueue.ts::enqueueJob(db, {targetId, jobType, payload, dedupWindow})` that:
  - Computes `idempotency_key = sha1(targetId|jobType|stableHash(payload)|floor(now/dedupWindow))`
  - Inserts with `ON CONFLICT (idempotency_key) DO NOTHING`
- Replace **all** `db.from('scan_jobs').insert({...job_type...})` call sites with `enqueueJob(...)`. grep says ~40 sites.
- Default window: 30 min for recon/discovery, 10 min for detectors, 5 min for mythos_step.

### 2. Extend loop-guard to the 5 remaining loopers

- Add `checkLoopGuard/recordLoopRun` to: `subdomain-enum`, `js-deep-expand`, `recon-engine`, `vuln-scanner`, `mythos-agent`.
- Tighten defaults: `maxRuns=3`, `stallStreak=2` for recon (currently 6/3).

### 3. Fix LLM fallback for empty `ai_provider_config`

- Rewrite provider selection in `_shared/llm.ts`:
  - On Lovable 402/429 → check `Deno.env` for `OPENAI_API_KEY`, `GEMINI_API_KEY`, `ANTHROPIC_API_KEY`, `OLLAMA_URL` **directly** (ignore `ai_provider_config.enabled` flag)
  - If ANY env key present → use it. Log which provider served the request.
  - If NONE → set global exhaustion sentinel and skip AI-dependent work cleanly (no re-queue).
- Add one status line to `scan_logs` explaining "no fallback provider configured" so user knows to add a key, instead of endless 402 spam.

### 4. Stop mythos-agent from re-firing on exhaustion

- In `mythos-agent`: before iteration loop, call `areCreditsRecentlyExhausted`. If true → mark run `paused`, do NOT enqueue next `mythos_step`.
- Currently it enqueues, worker picks it up, hits 402, logs error, requeues. That's the "🪫" spam.

### 5. phase-arbiter: dedup its own enqueues

- Before `insert into scan_jobs`, query for existing queued/running job of same (target, job_type) in last 15 min. Skip if present.
- (Idempotency helper from #1 handles this too, but this is belt-and-suspenders.)

### 6. Orphan/dead code sweep

- Grep for edge functions never referenced by any enqueue site or arbiter dispatch map. Report list to you; delete only after you confirm.

7. AI Hypothesis not working fix it. 

## Explicit non-goals (learning from last pass)

- No new detectors.
- No schema changes beyond the ones already applied.
- No UI changes.
- No "verify with 8 gates" theater — I'll paste actual dedup counts and one working AI call after the fix.

## Verification (small, real)

After the fixes, on your existing target `6308fd00-...`:

```sql
-- Should show job_type × count where max count << 5 (was 171)
SELECT job_type, count(*) FROM scan_jobs
 WHERE created_at > now() - interval '1 hour' GROUP BY 1 ORDER BY 2 DESC;
```

Plus one `ai_gateway_logs` line proving fallback fired (or a clean "no provider configured" log).

After it analyze all the functions and their codes deeply to find more issue which are stopping this tool to work like xbow. 

## Files touched (estimate)

- New: `supabase/functions/_shared/enqueue.ts` (~40 lines)
- Edited: `_shared/llm.ts`, `_shared/loop-guard.ts` (defaults), `mythos-agent`, `phase-arbiter`, `scan-job-worker`, plus ~5 detector modules for loop-guard, plus all enqueue call sites (mechanical replace).

Approve and I execute in one pass.