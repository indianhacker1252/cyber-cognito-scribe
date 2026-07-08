# CyberScope — Honest Gap Analysis & Fix Plan

Before writing more code, here is a straight accounting of what you asked for across the last several turns, what actually landed, what is still broken, and the root reason the tool still doesn't deliver end-to-end.

---

## 1. What you asked for (consolidated)

| # | Ask | Turn |
|---|-----|------|
| A | Fix OWASP checklist — only 1–2 categories actually get tested | multiple |
| B | Kill duplicate + fake findings, only real ones | multiple |
| C | Recon must discover *everything* before fuzzing (subdomains, endpoints, JS, params) | 3 |
| D | Stricter proof-oracle so detectors stop firing false positives | 3 |
| E | `chain-finder` + `exploit-engine` + `exploit-chain-runner` must execute multi-step chains end-to-end | 3 |
| F | `ai-strategist` + `mythos-debate` need richer context and a tight tool-use loop | 3 |
| G | Run a real E2E scan on one target and prove A01–A10 all fire | 3 |
| H | NVD must actually be checked against the target | 5 |
| I | OWASP checklist "target delete mismatch" error | 5 |
| J | Progress bar for running/pending/completed jobs | 6 |
| K | Neural log must show what the AI is doing *right now* + next step + debate transcript | 6 |
| L | Ability to start / abort / restart scan from the UI | 6 |
| M | Findings-audit report + provenance panel per finding | 6 |
| N | Fix orphaned OWASP checklist rows that can't be deleted | 6 |
| O | Kill functions that return demo/stub data | 6 |
| P | Update README | 6 |

---

## 2. What was actually delivered

**Landed and working:**
- Dedup trigger `trg_auto_dedup_finding` + backfill — verified 0 collisions.
- `delete_owasp_checklist` RPC accepts UUID / name / domain — orphan deletion works.
- Provenance tab in `FindingDetailsDialog`.
- `nvd-intel-sync` widened to running/queued/in_progress targets.
- `phase-arbiter` diagnose/resume actions.
- `_shared/triple-verify.ts` timing + redirect + IDOR + auth-bypass oracles.
- `ai-strategist` richer context + proofNonce enforcement.
- `_shared/waf-detect.ts` and `_shared/exploit-guards.ts` syntax fixes (unblocked deploys).
- `e2e-selftest` schema fix.
- README updated.

**Claimed but not verified:**
- E2E scan on `testphp.vulnweb.com` — never showed the phase table, findings count, or A01–A10 fire evidence you asked for in ask G.
- "System Health dashboard with per-target progress bars + bulk cancel" — referenced as pre-existing; not confirmed against the current `SystemHealth.tsx` in this session.
- Chain/exploit runners "redeployed" but no proof they actually executed a chain.

**Never delivered:**
- **K** — Live "what AI is doing now / next step" stream in Neural Log, and `mythos-debate` transcript surfacing.
- **L** — Explicit start/abort/restart controls wired from a single scan-control panel.
- **O** — Sweep of functions that still return demo/stub data (no audit was produced).
- **G** — Actual A01–A10 fire evidence from a real run.
- **C** — Recon depth improvements were touched in `subdomain-enum` only; `recon-engine`, `recon-deep`, `js-deep-expand`, `openapi-importer`, `route-fingerprint` were not audited together.

---

## 3. Why the tool still isn't working (root causes)

1. **No single source of truth for "is a scan actually progressing".** `phase-arbiter`, `scan-job-worker`, `scan_phase_state`, `scan_jobs`, and per-module heartbeats all exist but disagree. When they disagree, nothing advances and no one sees it.
2. **Fan-out is still partial.** OWASP shows 1–2 categories because most detectors only cover 1–2 checklist entries each, and the checklist seeder + detector `check_name` writes are not aligned. It's not that jobs aren't running — it's that they run and don't tick their boxes.
3. **Exploit chain never closes the loop.** `chain-finder` writes edges, `exploit-engine` runs single primitives, `exploit-chain-runner` exists — but nothing hands a confirmed primitive back into the chain executor with session state. Result: chains stay theoretical.
4. **AI loop is fire-and-forget.** `ai-strategist` generates hypotheses, but there is no visible feedback into `mythos-debate`, no round-2 mutation, and no user-visible transcript. So it *looks* like the AI is doing nothing.
5. **Demo/stub returns still exist in several functions.** Suspected: parts of `mythos-*`, `zeroday-engine`, `live-cve-runner`, `intel-sync`. Never audited.
6. **UI doesn't expose the truth.** Even when the pipeline is healthy, there's no live job counter, no per-phase progress, no debate feed, no abort button. So every partial run *looks* like a total failure.
7. **My previous turns over-claimed.** Several "verified" / "redeployed" statements were not backed by a screenshot, a log excerpt, or a SQL result. That's the deeper reason you keep hitting the same wall — the fix landed in code but was never proven against a live target.

---

## 4. Proposed fix plan (one focused pass, in this order)

### Phase 1 — Truth & Visibility (do this first, everything else depends on it)
- **Neural Log live feed:** subscribe to `scan_logs` + `scan_phase_state` + `attack_hypotheses` + `mythos_debate_messages` via Realtime; render "NOW / NEXT / DEBATE" columns.
- **Scan Control panel** on Targets page: Start / Abort / Restart-from-phase, with per-target progress bar reading `scan_phase_state` + counts from `scan_jobs`.
- **Job counter chip** in the header: running / queued / failed globally.

### Phase 2 — OWASP Checklist Actually Ticks
- Audit every detector's `check_name` writes against the seeded checklist rows; produce a coverage matrix.
- Add missing detector→check mappings so each A0x has ≥1 detector that ticks it.
- Arbiter refuses `owasp_matrix = complete` until ≥90% attempted (already coded, verify it fires).

### Phase 3 — Real E2E Proof Run
- Fire `e2e-selftest` against `testphp.vulnweb.com`.
- Poll every 60s for 15 min. At the end paste: phase table, per-A0x fire count, findings count, dedup drops, exploit_runs, hypothesis rounds, mythos debate rounds.
- If any row is 0 → open a fix ticket for that specific module, don't hand-wave.

### Phase 4 — Chain Execution Closes the Loop
- Wire `exploit-engine` success → append to `exploit_chain_runs.session_state` → invoke `exploit-chain-runner` with the token/cookie/param carried forward.
- Kill-chain graph edges only get `confirmed=true` when the downstream step re-fires with the upstream artifact.

### Phase 5 — Demo/Stub Sweep
- Grep every edge function for `TODO`, `mock`, `example.com`, `demo`, hardcoded finding text; produce a list; replace or delete.

### Phase 6 — README & Ops
- Document the new UI panels, control endpoints, and the E2E proof-run command.

---

## 5. What I will NOT do this pass

- No new detectors, no new AI providers, no schema redesigns.
- No claims of "verified" without a pasted SQL row or screenshot.

---

## 6. Deliverable at the end of the pass

A single reply containing:
1. The E2E proof table from Phase 3.
2. Screenshots of the new Neural Log live feed and Scan Control panel.
3. The stub-sweep audit list with actions taken.
4. Any remaining known gaps, named honestly.

Approve this and I execute Phases 1→6 in order, with the proof run as the acceptance gate.
