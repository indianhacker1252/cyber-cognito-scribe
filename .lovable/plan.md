# CyberScope — Bulletproof Fix Plan (root-cause pass)

This plan replaces the previous phased plan. It attacks every symptom you listed by its **root cause**, not its surface. No new features until the pipeline is honest.

---

## 1. Symptoms you reported → root cause map


| #   | Symptom                                                                                                  | Root cause                                                                                                                                                                                                                      |
| --- | -------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Functions running in a loop, same fn many times                                                          | `scan-job-worker` re-enqueues on any non-success; no idempotency key on jobs; `phase-arbiter` re-schedules a phase whose jobs are still `queued`                                                                                |
| 2   | Passive / code / other findings missing from Findings tab                                                | `Findings.tsx` filters by `source in (scanner set)` and by `validation_status`; passive + code sources are excluded by the query, not by the data                                                                               |
| 3   | Matrix findings are false positives                                                                      | `detectProof` in `injection-matrix.ts` accepts weak signals (status echo, generic error strings). No triple-verify gate before write                                                                                            |
| 4   | Discovery runs in a loop                                                                                 | `recon-engine` + `subdomain-enum` + `recon-deep` all re-queue themselves; no `phase_completed_at` guard                                                                                                                         |
| 5   | Only 2/7 phases tested                                                                                   | `phase-arbiter` advances on job-count = 0 but jobs are silently dropped by `block_orphan_mythos_steps` and by worker timeouts; arbiter treats "no jobs" as "phase done"                                                         |
| 6   | NVD not checked against target tech                                                                      | `nvd-intel-sync` runs global sync, never joins to `discovered_endpoints.tech` / `scan_assets.tech`; `cve-version-matcher` is not invoked per-target after recon                                                                 |
| 7   | Exploit testing repeats same probes, no confirmation                                                     | `exploit-engine` refetches baseline from `affected_url` = probe URL for legacy rows; no state carry; no proof-nonce check on second fetch                                                                                       |
| 8   | 3/83 OWASP done, rerun does nothing                                                                      | `enqueue_missing_owasp_modules` only queues when `active_jobs = 0`; worker never drains because of loop (#1), so rerun is a no-op                                                                                               |
| 9   | recon-juicy, form-attacker, race-runner, business-logic-fuzzer, js-deep-expand, matrix-fuzzer not firing | Not registered in `scan-job-worker` dispatch table for their `job_type`; queued but never picked up                                                                                                                             |
| 10  | Kill chain empty                                                                                         | `kill-chain-graph` only builds from `attack_graph_edges` where `confirmed=true`; nothing ever sets confirmed                                                                                                                    |
| 11  | Fake / guessed finding data                                                                              | `mythos-*`, `zeroday-engine`, `live-cve-runner` return synthesized text without a real HTTP round-trip                                                                                                                          |
| 12  | AI hypothesis not working                                                                                | `ai-strategist` writes to `attack_hypotheses` but `hypothesis-test-runner` is not enqueued after write                                                                                                                          |
| 13  | AI "exhausted" instead of falling back                                                                   | `_shared/llm.ts` catches 402/429 and returns error object; fallback chain (Gemini→Claude→OpenAI) is coded but the switch is gated on `providerConfig.enabled` which defaults false                                              |
| 14  | Phases run out of order (subdomain-enum mid-scan)                                                        | `phase-arbiter` uses `priority` not `phase_order`; recon jobs get re-queued by discovery detectors mid-fuzz                                                                                                                     |
| 15  | Requests/responses not intercepted/re-tested                                                             | `request-repeater` + `request-mutator` exist but are never called from arbiter; no auto-replay after finding                                                                                                                    |
| 16  | AI guesses instead of reasoning                                                                          | System prompt in `ai-strategist` / `vapt-chat` doesn't force tool-use; no ReAct loop, no evidence citation                                                                                                                      |
| 17  | IP / LLM / Package / API testing failed                                                                  | Each has its own broken entry: IP scan = missing `deep-asset-scan` dispatch; LLM = `llm-attack-suite` returns 500 on missing endpoint; Package = `app-package-scan` bucket path wrong; API = `openapi-importer` never scheduled |


---

## 2. Fix strategy (single pass, root-cause order)

### A. Kill the loops (fixes #1, #4, #8)

1. Add `idempotency_key` column to `scan_jobs` = hash(target_id, job_type, payload_digest, phase). Unique partial index on `(status in ('queued','running'))`.
2. `scan-job-worker`: before enqueueing a child job, check idempotency_key; if exists in queued/running → skip.
3. `phase-arbiter`: a phase advances only when `count(queued)+count(running) = 0` AND `heartbeat < 5min` on every declared module for that phase. Otherwise mark `stuck` (not `complete`).
4. Add `scan_phase_state.expected_modules text[]` seeded per-phase so arbiter can prove coverage.

### B. Restore worker dispatch (fixes #9, #17)

5. Rebuild `scan-job-worker` dispatch map with an explicit `JOB_TYPE → function-name` table. Include every module you named: `recon-juicy`, `form-attacker`, `race-runner`, `business-logic-fuzzer`, `js-deep-expand`, `matrix-fuzzer`, `deep-asset-scan` (IP), `llm-attack-suite`, `app-package-scan`, `openapi-importer`.
6. Add a self-test edge fn `worker-selftest` that enqueues one no-op of every registered job_type and confirms it drains within 60s. Fail loudly.

### C. Real findings only (fixes #3, #11)

7. `injection-matrix.detectProof`: replace weak string matches with proof-tier ladder — reflected-marker + status-delta + length-delta > 25% + WAF-signature check. Anything below tier 2 → write to `finding_evidence` staging, not `vulnerability_findings`.
8. Every writer path calls `triple-verify` synchronously before insert. Fail-closed: no verify → no finding.
9. Delete synthesis paths in `mythos-agent`, `zeroday-engine`, `live-cve-runner`. Replace with "must have request_raw + response_raw or reject".
10. Add DB check constraint: `vulnerability_findings` requires non-null `request_raw` and `response_raw` for severities ≥ high.

### D. NVD → target actually joins (fixes #6)

11. After `recon-engine` writes `scan_assets.tech`, arbiter enqueues `cve-version-matcher` with `{targetId, tech[]}`. Matcher joins to `nvd_intel` by CPE and writes findings with `finding_type='cve_match'` + CVSS. Then enqueues `cve-to-exploit`.

### E. Exploit loop closes (fixes #7, #10)

12. `exploit-engine` on success writes `exploit_runs.session_state` (cookies, tokens, params). Then invokes `exploit-chain-runner` with the state; runner walks `attack_graph_edges` and re-fires downstream primitives carrying the state.
13. Edge sets `confirmed=true` only when downstream primitive re-fires with upstream artifact and re-triggers proof-nonce. `kill-chain-graph` reads confirmed edges → kill chain populates.

### F. AI actually reasons and falls back (fixes #12, #13, #16)

14. `_shared/llm.ts` fallback chain becomes unconditional: try Lovable/Gemini → Anthropic → OpenAI → Ollama regardless of `ai_provider_config.enabled`; log which one served each call.
15. `ai-strategist` writes hypothesis → immediately enqueues `hypothesis-test-runner` job with the hypothesis id. Runner reports back into `mythos_debate` with a follow-up round.
16. Rewrite `ai-strategist` + `vapt-chat` system prompts to ReAct format: `THOUGHT → TOOL(name,args) → OBSERVATION → …`; refuse to emit a finding without at least one `OBSERVATION` block containing a real HTTP response snippet.

### G. Phases run in order + requests are re-tested (fixes #14, #15)

17. `phase-arbiter` uses new column `scan_phase_state.phase_order int` (1..7); worker refuses to pick a job whose phase_order > current+0. Discovery detectors write to `discovered_endpoints` but do NOT enqueue new recon jobs mid-fuzz.
18. After every confirmed finding, arbiter enqueues `request-repeater` (replays original) and `request-mutator` (10 mutations) to find sibling bugs. Results tie back to the parent finding via `parent_finding_id`.

### H. Findings tab shows everything (fixes #2)

19. `Findings.tsx` query drops the `source` allow-list; adds a source facet filter (default = all). Passive + code + package + API findings become visible immediately.

### I. Visibility (so we never regress silently)

20. `BrainPanel` already streams `attack_hypotheses`; add `mythos_debates`, `hypothesis_test_runs`, and the LLM provider actually used per call.
21. `ScanControl` adds a per-phase row with expected_modules vs modules_with_heartbeat, so a stuck phase shows in red.

---

## 3. Verification gates (nothing ships without these)

Run against `testaspnet.vulnweb.com`:

- **G1** — 7/7 phases advance; `scan_phase_state.status` = complete for each with `expected_modules ⊆ modules_with_heartbeat`.
- **G2** — Each of the named modules (recon-juicy, form-attacker, race-runner, business-logic-fuzzer, js-deep-expand, matrix-fuzzer, deep-asset-scan, llm-attack-suite, app-package-scan, openapi-importer) has ≥1 successful run row.
- **G3** — OWASP checklist ≥ 70/83 rows in `attempted|evidence|passed` (was 3/83).
- **G4** — Every `vulnerability_findings` row of severity ≥ high has non-null `request_raw` + `response_raw`.
- **G5** — At least 1 `nvd_intel` CVE joined to `scan_assets.tech` and written as a `cve_match` finding.
- **G6** — At least 1 `kill_chains` row with `confirmed_edges > 1`.
- **G7** — `ai_gateway_logs` shows fallback provider actually used when primary returns 402/429.
- **G8** — Findings tab returns rows for `source in ('passive','code','package','api')`.

Any gate failing = fix that gate before claiming done. Results pasted as SQL output, not prose.

---

## 4. Technical execution order

```text
1. Migration: idempotency_key, phase_order, expected_modules, parent_finding_id, request/response NOT NULL check
2. _shared/llm.ts: unconditional fallback + provider logging
3. scan-job-worker: dispatch map rebuild + idempotency guard
4. phase-arbiter: phase_order gate + expected_modules coverage gate
5. injection-matrix + findings-writer: proof-tier ladder + mandatory triple-verify
6. Delete synthesis in mythos-agent, zeroday-engine, live-cve-runner
7. cve-version-matcher wiring after recon
8. exploit-engine → exploit-chain-runner state handoff; kill-chain confirmed edges
9. ai-strategist → hypothesis-test-runner enqueue; ReAct prompts
10. request-repeater / request-mutator auto-enqueue after finding
11. Findings.tsx source filter
12. BrainPanel + ScanControl phase-coverage rows
13. worker-selftest edge fn
14. E2E run against testphp.vulnweb.com; paste all G1–G8 outputs
```

---

## 5. What I will NOT do

- No new detectors, no new AI providers, no schema redesigns beyond the columns above.
- No "verified" claim without a pasted SQL row from the target run.
- No stub/demo data anywhere in the fix.

---

## I'll implement and fix all these errors in single fix and now don't need any permission from you. I'll execute the testing plan in same implementation to find  the existing errors.