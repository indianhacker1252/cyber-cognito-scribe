# Gap Analysis: Our Tool vs XBOW / Mythos

## Where we stand today
- **Long-lived agent runtime** (`runtime/`) with ReAct loop, browser (Playwright), HTTP, shell allowlist (subfinder/httpx/katana/nuclei/sqlmap/dalfox/...), OOB (interactsh), proxy replay, memory + findings tools.
- **World model** table + agent_sessions / agent_events / planner_traces with RLS.
- **Edge functions** (~120) for legacy phase-based scanning, kept in parallel.
- **Installer** provisions Ollama, PD suite, exploit CLIs, interactsh, mitmproxy, systemd units, doctor selftest.
- **Bench harness** (Juice Shop / DVWA / WebGoat) with precision/recall scorer.

## Real gaps vs XBOW / Mythos

### 1. Agent brain is too shallow (biggest gap)
- Single system prompt, one flat message, no scratchpad, no belief/hypothesis tracking between steps.
- No planner ↔ executor split (XBOW runs a planner that emits sub-goals, executor that runs tools, critic that scores proof).
- No cost/step budget accounting fed back to the model.
- No retry-on-tool-error with reflection; tool failure just becomes another observation.

### 2. Memory is a JSON blob, not retrievable knowledge
- `world_model` merged with shallow patch; no vector recall, no per-endpoint notes, no "prior attempt" index the model queries.
- Findings from edge-function scanners are not surfaced back into the agent's context.

### 3. Weak proof discipline
- `findings.record` trusts the model's `proof_tier`. No server-side oracle check before insert (SQLi baseline diff, XSS DOM alert capture, SSRF OOB match, IDOR cross-account replay).
- No screenshot / HAR / raw-request artifact storage per finding.

### 4. Recon is broad but not correlated
- Subfinder → httpx → katana run as isolated tool calls. Results are not deduped, scored, or turned into a ranked attack surface the planner iterates over.
- No JS secret / API route extraction from katana output feeding back into fuzzers.

### 5. Exploit chaining is not real
- `chain-finder` / `exploit-chain-runner` exist as edge functions but the long-lived agent never invokes them and has no in-runtime chain executor with shared session/cookie state.

### 6. No differential / multi-session testing
- Auth-bypass and IDOR need two authenticated contexts side by side. Agent has one browser context.

### 7. Learning loop is stubbed
- Bench scorer writes history.json but nothing feeds precision/recall back into payload ranking or prompt selection.

### 8. Observability
- `BrainPanel` shows events but no per-session cost, tokens, tool-latency, or proof-oracle verdicts.

## Fix plan (ordered by ROI)

### P1 — Planner / Executor / Critic split (runtime)
- Split `operator.ts` into `planner.ts` (emits next sub-goal + success criteria), `executor.ts` (current tool loop, scoped to one sub-goal), `critic.ts` (scores whether success criteria met, decides continue/abandon).
- Persist each as `agent_events` of type `plan` / `act` / `critique` so `BrainPanel` renders three lanes.

### P2 — Deterministic proof gate in `findings.record`
- Before insert, re-run a proof oracle in-runtime:
  - SQLi: baseline vs payload timing/error diff via `http.request`.
  - Reflected/DOM XSS: `browser.exec_js` dialog capture.
  - SSRF: match `oob.poll` for correlation_id in evidence.
  - Open redirect: parse `Location` host != target host.
- Reject with reason if oracle fails; downgrade to `suspected` only when explicitly allowed.

### P3 — Structured memory
- New tables: `agent_notes(target_id, kind, key, value, embedding)` and `endpoint_catalog(target_id, url, method, params, auth_required, tech, last_probed, verdicts jsonb)`.
- New tools: `memory.query(kind, key_like)`, `endpoints.list(filter)`, `endpoints.mark(url, verdict)`.
- Recon tools write into `endpoint_catalog` instead of blob.

### P4 — In-runtime chain executor
- Port `chain-finder` logic into `runtime/src/chains.ts` with shared cookie jar across steps.
- New tool `chain.run(steps)` that executes ordered http/browser calls and returns aggregated proof.

### P5 — Multi-context auth testing
- Agent supports N named browser contexts (`browser.visit({ context: "userA" })`).
- New tool `auth.login(context, creds)` + `auth.compare(url, ctxA, ctxB)` for IDOR/BAC proofs.

### P6 — Learning loop closes
- After each session, compute per-technique success rate, write to `technique_stats`.
- `ai-mutator` UCB1 reads `technique_stats` for arm priors.
- Nightly bench run posts precision/recall delta to a `bench_runs` table; UI card in Diagnostics.

### P7 — Observability
- Record token count + cost + latency per step in `agent_events.meta`.
- BrainPanel: cost meter, tool-latency histogram, proof-oracle pass/fail badges.

## Honest verdict
We match XBOW/Mythos on **surface capability** (long-lived runtime, browser, OOB, PD-suite, shell). We lose on **agent reasoning depth, proof rigor, and learning loop**. P1 + P2 + P3 close ~70% of the qualitative gap; P4–P7 close the rest.

## Next step
Approve this plan and I'll ship P1 + P2 in the next turn (runtime-only, no schema churn beyond one new column on `agent_events`).
