# Pro-Level VAPT Upgrade Plan (Beat XBOW/Mythos)

Goal: move from "scanner + AI gate" to a true **autonomous exploit agent** with reasoning traces, deterministic proofs, and closed-loop learning — the same primitives that make XBOW and Mythos effective.

The current tool already has: confidence gate, CVE mapper, loop guard, adaptive lessons, phase arbiter, dedup trigger. The gap vs. XBOW is in **agentic reasoning depth, proof determinism, and per-target world-modeling** — not in more scanners. This plan targets those.

---

## Pass A — World Model per Target (foundation for everything else)
Right now every module re-derives context from scratch. XBOW keeps a persistent "target belief state".

1. New table `target_world_model` (jsonb): tech stack, auth model, routing style (SPA/MPA/API), auth cookies, CSRF style, WAF vendor, rate-limit profile, interesting params, sinks/sources seen in JS.
2. New shared `_shared/world-model.ts` with `getWorld(targetId)` / `updateWorld(targetId, patch)`.
3. `recon-engine`, `js-deep-expand`, `waf-detect`, `route-fingerprint`, `auth-deep` all write into it.
4. Every detector reads world state and **skips classes that don't apply** (e.g. no SSTI probes on a static site).

## Pass B — Agentic Planner (replace phase-arbiter's static PHASE_ORDER)
XBOW's edge is LLM-driven step selection with tool-use, not fixed phases.

1. New `agent-planner` edge function: input = world model + open findings + remaining OWASP checks; output = next 3 concrete tool calls with expected evidence.
2. Structured tool-call schema (JSON) — planner emits `{module, target_url, params, expected_signal}`.
3. `phase-arbiter` keeps ordering as a *safety rail* but delegates module selection to `agent-planner` once recon is complete.
4. All planner turns land in `neural_log` with trace IDs so the Brain panel shows real chain-of-thought.

## Pass C — Deterministic Proof Oracles (kill remaining FPs)
Confidence score alone isn't enough. Each vuln class needs a **deterministic oracle** that either fires or doesn't.

1. `_shared/proof-oracles.ts` with per-class checks:
   - XSS → headless-browser dialog event + nonce
   - SQLi → boolean pair delta + timing pair + DB error regex
   - SSRF → OOB callback OR internal-only IP response fingerprint
   - IDOR → cross-account differential with identical schema
   - RCE → OOB DNS/HTTP with unique token OR reflected `uid=` pattern
   - Open redirect → real 30x Location to attacker host
   - Auth bypass → 200 + expected-only content marker
2. Findings-writer requires oracle-pass **OR** confidence ≥90 with hard marker.
3. Oracle results stored in `finding_evidence.oracle_result` for the Provenance tab.

## Pass D — Exploit Chain Executor (real end-to-end chains)
Chain-finder proposes chains; nothing actually runs them multi-step with shared state.

1. New `_shared/exploit-runtime.ts`: session jar + variable substitution (`{{step1.token}}`), retry, per-step assertion.
2. `exploit-chain-runner` rewritten to consume `ChainStep[]` from planner or chain-finder and execute sequentially with rollback logging.
3. Success = final-step oracle passes. Chain gets its own `kill_chain` record with severity = max(step severities) + 1 tier.

## Pass E — Adaptive Payload Engine (mutation as reasoning, not lookup)
Today `ai-mutator` learns per class. Upgrade to per (class, waf, tech, param-context).

1. Extend `adaptive_lessons` with `context_hash` (waf+tech+param-type).
2. `mutateWithAi` scores lessons via UCB1 (exploration/exploitation) instead of "top 5 success".
3. Feed **failed** mutations back too — negative examples shrink the prompt search space.

## Pass F — Live Neural Brain UI
Make the reasoning visible so it *feels* like Mythos.

1. `BrainPanel` streams three lanes: **Plan** (planner), **Act** (running modules), **Observe** (oracle results).
2. Add "Ask Brain why" button on every finding → replays the planner trace that produced it.

## Pass G — Cleanup / correctness
- Delete truly orphaned functions (audit list generated first, then removed).
- Drop noisy cron logs (`enqueue_missing_owasp_modules` already fixed — extend the pattern to `fail_stuck_mythos_runs`, phase-arbiter tick).
- Move all direct `vulnerability_findings` inserts to `recordFinding` (trigger already demotes, but source-fix is cleaner).

---

## Delivery order (one implementation pass each so you can review)

1. **Pass A + G-partial** — world model + orphan cleanup (foundation, low risk)
2. **Pass C** — proof oracles (biggest FP reduction, immediate quality jump)
3. **Pass B** — agentic planner (unlocks XBOW-style behavior)
4. **Pass D** — chain executor
5. **Pass E** — UCB1 mutator
6. **Pass F** — Brain UI upgrade

Each pass is self-contained, deployable, and independently testable.

## Technical notes
- All new tables get `GRANT` + RLS per project rules.
- Planner and oracles run inside existing `scan-job-worker` fanout — no new cron.
- `world-model.ts` uses a single row per target with jsonb patch merging to avoid write contention.
- LLM calls route through existing `llm.ts` fallback chain — no new provider wiring.

Confirm and I'll ship Pass A immediately, then continue through Pass F in order.
