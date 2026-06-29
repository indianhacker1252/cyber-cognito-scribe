# Plan — Make CyberScope Actually Work End-to-End

The pipeline keeps "looking" complete but never delivers because six independent breakages compound each other. This plan fixes them in one coordinated pass, then proves it with a forced end-to-end run.

## Root causes (verified against current code + DB)

1. **Fan-out is one-directional.** `scan-job-worker`'s post-recon fan-out enqueues many modules, but most modules don't call each other. If `recon` partially fails (very common on http-only / WAF'd hosts), the chain never starts. There is no "phase complete → next phase" arbiter.
2. **OWASP scan never finishes.** `owasp_coverage` is written per-finding only, not per-check. There is no per-category checklist that says "A01..A10 all attempted" → UI shows partial forever.
3. **Exploit engine starves.** Findings only auto-enqueue exploit jobs when severity is high/critical OR proof tier is reflected/indicator/suspected. Matrix-fuzzer + heuristics mostly write `medium`/`signal`, so nothing reaches `exploit-engine`.
4. **Duplicates + false positives.**
  - `vulnerability_findings` has no DB-level unique constraint; the in-code dedupe key is `(target, source, payload)` which misses same-bug-different-payload and same-param-different-URL-noise.
  - 3xx guard exists but per-param noise (status-only diffs, length jitter < 5%) still passes.
5. **AI doesn't reason deep.** `triage-brain` is called per finding in isolation. No cross-finding correlation, no asset-graph context, no "hypothesis → mutate → re-fire" loop wired into the worker.
6. **Subdomains ignored.** `expandScope` exists and `scan_assets` is populated, but most modules (recon-juicy, advanced-fuzzer, llm-attack-suite, ssrf-deep, form-attacker for non-discovered forms) still read `target_workspaces.domain` and attack only the apex.

## Fix plan (single coordinated implementation)

### A. Phase arbiter (fixes #1, #2)

- New table `scan_phase_state(target_id, phase, status, checks_attempted, checks_passed, last_heartbeat)`.
- New edge function `phase-arbiter`:
  - Runs every minute via pg_cron + after every job completes.
  - For each active target: checks which phases have heartbeat in last 5 min; if a phase is `running` with no heartbeat → mark `failed` and force-fan-out the next phase.
  - Phases: `recon → discovery → owasp_matrix → deep_modules → exploit → chain → report`.
- Each module writes a heartbeat row on start + on each batch. No more silent stalls.

### B. OWASP completion ledger (fixes #2)

- New table `owasp_checklist(target_id, category, check_name, status, evidence_count)` seeded with the full A01–A10 check list (≈45 rows per target).
- Every detector writes `check_name` it covered. UI/Coverage page reads checklist → real %.
- Arbiter refuses to mark `owasp_matrix` complete until ≥90% of checks attempted.

### C. Exploit engine wiring (fixes #3)

- In `findings-writer.ts`: enqueue exploit job whenever proof tier is `signal`+ AND `vulnClass` is in `{xss, sqli, ssrf, ssti, rce, lfi, idor, xxe, redirect}` regardless of severity.
- Add `exploit-engine` watchdog: if a target has ≥1 finding and 0 exploit_runs after 3 min → force-enqueue top 10 findings.
- Add `exploit_runs.confirmed_proof` link back to finding for UI.

### D. Dedupe + FP killer (fixes #4)

- DB migration: `CREATE UNIQUE INDEX vf_dedup_idx ON vulnerability_findings (target_id, finding_type, COALESCE(affected_url,''), COALESCE(payload,''))` + switch insert to upsert(ignoreDuplicates).
- In `findings-writer.ts`:
  - Hash `(host, method, path-without-id-segments, param, vulnClass)` → `dedup_key` column; reject inserts with existing key in last 24h.
  - Add response-similarity filter: require ≥5% length delta AND status change OR a proof marker. Status-only 200→200 with <2% delta = drop.
  - Drop 401/403 findings unless source is BAC/auth.

### E. AI deep-reasoning loop (fixes #5)

- New function `ai-strategist` invoked by arbiter at end of `owasp_matrix`:
  - Inputs: full asset graph, all findings, tech stack, WAF profile, OOB hits.
  - Outputs: `attack_hypotheses` rows with target endpoint + mutation idea + expected proof marker.
  - Each hypothesis becomes a `scan_job` of type `hypothesis_test` that runs the mutation and updates the hypothesis row with result. Feeds back to strategist for round 2 (max 3 rounds).
- `llm-attack-suite` upgraded: receives hypothesis context, not just raw URL.

### F. Subdomain fan-out (fixes #6)

- All scanners switched from reading `target_workspaces.domain` to iterating `scan_assets` via `expandScope`.
- Affected: `recon-juicy`, `advanced-fuzzer`, `llm-attack-suite`, `ssrf-deep`, `cve-to-exploit`, `waf-evasion-engine`, `chain-exploit`, `form-attacker`.
- Add per-asset `scan_assets.phase_state` so UI shows progress per subdomain.

### G. Proof + verification gate (clean reports)

- `validate-finding` mandatory before a finding becomes UI-visible `confirmed`. Anything below stays in "candidates" tab.
- Two-engine corroboration: a finding needs hits from ≥2 of {matrix-fuzzer, advanced-fuzzer, llm-attack-suite, exploit-engine} OR a hard proof marker.

### H. Verification run

- After deploy, force-trigger fresh recon on the current workspace.
- Poll `scan_phase_state` for 15 min and paste the assertion table (phase, status, checks_passed, findings, exploits, dedupes dropped).
- If any phase stalls → arbiter logs the reason; we fix and re-run.

## Deliverables in this single implementation

**Migrations:** `scan_phase_state`, `owasp_checklist` + seed, `vulnerability_findings.dedup_key` + unique index, `attack_hypotheses`, `scan_assets.phase_state`.

**New edge functions:** `phase-arbiter`, `ai-strategist`, `hypothesis-test-runner`, `exploit-watchdog`.

**Updated edge functions:** `findings-writer.ts` (dedupe + FP gate + broader exploit enqueue), `scan-job-worker` (heartbeat + arbiter dispatch), `recon-juicy`, `advanced-fuzzer`, `llm-attack-suite`, `ssrf-deep`, `cve-to-exploit`, `waf-evasion-engine`, `chain-exploit`, `form-attacker`, `triage-brain` (cross-finding context).

**Cron:** 1-min `phase-arbiter`, 2-min `exploit-watchdog`, 10-min stuck-run sweeper (already exists, extend).

**UI:** Coverage page reads `owasp_checklist`; Targets page shows per-asset progress; Findings page hides un-validated unless toggle.

## Technical notes

- Heartbeat: `UPDATE scan_phase_state SET last_heartbeat=now() WHERE …` once per asset per module, cheap.
- Dedup key normalization strips numeric path segments (`/user/123` → `/user/:id`) and sorts query keys.
- Hypothesis loop bounded: ≤3 rounds, ≤30 hypotheses/round, hard timeout 8 min total.
- All new functions use `EdgeRuntime.waitUntil` + 200-ack pattern to avoid 150s gateway timeout.

## Sequence

1. Migrations (single file).
2. Shared helpers (`dedup-key.ts`, `phase-heartbeat.ts`, `asset-iterator.ts`).
3. New functions (4).
4. Update existing functions (11) to use helpers + iterate `scan_assets`.
5. Cron schedule.
6. Force fresh recon → paste results.

In recon it must check for  all posible information to report. 

Approving this plan will execute all steps in one implementation pass and end with the proof run.