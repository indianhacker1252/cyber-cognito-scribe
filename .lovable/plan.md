# Option B — Rebuild as a real XBOW-style agent

The current tool is a **stateless fan-out of edge functions** capped at 50s each, orchestrated by cron ticks. XBOW/Mythos are **long-lived agents** with a single reasoning loop, a persistent target state, and real tools (browser, shell, HTTP proxy) they can call for minutes/hours. To match that, we replace the orchestration layer, not the detectors.

The Supabase database and the existing detector code become the **tool surface** for a new agent runtime that lives outside edge functions.

---

## Target architecture

```text
   ┌─────────────────────── Lovable UI (unchanged shell) ───────────────────────┐
   │  BrainPanel · Findings · OWASP · Diagnostics · ScanControl                 │
   └───────────────▲──────────────────────────────────────────────▲─────────────┘
                   │ Supabase Realtime (agent_events, findings)   │ REST
                   │                                              │
   ┌───────────────┴──────────────────────────┐    ┌──────────────┴─────────────┐
   │  Agent Runtime  (long-lived worker)      │    │  Supabase (state + tools)  │
   │  ────────────────────────────────────    │    │  target_world_model        │
   │  • Per-target Operator loop (hours)      │◄──►│  agent_sessions            │
   │  • LLM: Gemini / GPT / Claude via SDK    │    │  agent_events (append-log) │
   │  • ReAct: plan → tool → observe → learn  │    │  tool_invocations          │
   │  • Tools: http, browser, shell, oracle,  │    │  findings + evidence       │
   │    cve, mutator, chain-runner            │    │  owasp_checklist           │
   └──────────────┬───────────────────────────┘    └────────────────────────────┘
                  │
                  ▼
     Playwright browser · headless shell · HTTP client with proxy · OOB listener
```

Key idea: **one agent per target**, not 154 jobs per target. The agent decides what to do next; edge functions become dumb tool endpoints it can call when it wants a fanned-out primitive.

---

## Phase plan (concrete, in build order)

### Phase 1 — Runtime host (unblocks everything)

Edge Functions cannot host this. Pick one:

- **Recommended:** Fly.io Machine (or Railway) running a Node/TS worker container. One machine per active target, autoscaled. Cheap, long-lived, has shell + browser.
- Alternative: a single always-on VPS with a queue.

Deliverables:
- `runtime/` folder in repo with Dockerfile, `pnpm start` boots the agent.
- Supabase service-role key + `LOVABLE_API_KEY` injected as env.
- Health endpoint + graceful shutdown on SIGTERM (checkpoints state).

### Phase 2 — State model (single source of truth)

Add tables (keep existing ones):
- `agent_sessions(id, target_id, status, started_at, ended_at, budget_credits, budget_seconds)`
- `agent_events(id, session_id, ts, kind, payload jsonb)` — append-only log the UI streams via Realtime. `kind ∈ {plan, thought, tool_call, tool_result, finding, decision, error}`.
- `tool_invocations(id, session_id, tool, args, result, latency_ms, cost_credits)`

Retire `scan_jobs` fan-out as the orchestrator (keep table for the few background primitives the agent still fans out).

### Phase 3 — Operator loop (the "brain")

One file: `runtime/src/operator.ts`.

```ts
while (!done && withinBudget()) {
  const ctx = await loadWorldModel(targetId);
  const plan = await llm.plan(ctx, recentEvents);   // structured: next_tool + why
  emit('plan', plan);
  const result = await tools[plan.tool](plan.args); // real tool call
  emit('tool_result', result);
  await updateWorldModel(targetId, plan, result);   // learn
  done = plan.tool === 'finish' || goalMet(ctx);
}
```

Rules:
- Uses AI SDK `streamText` + tool calling with `stopWhen: stepCountIs(200)`.
- Every step persisted to `agent_events` before the next LLM call (crash-safe resume).
- Model = `google/gemini-3.6-flash` default, fallback chain unchanged.

### Phase 4 — Tool surface (what the agent can actually do)

Real tools, not "queue a job":

| Tool | Impl |
| --- | --- |
| `http.request` | Node fetch through mitm proxy; records req/resp to evidence |
| `browser.visit` | Playwright page; returns DOM, console, network, screenshot |
| `browser.exec_js` | For DOM XSS / prototype pollution proofs |
| `shell.run` | Sandboxed `bash -c` (nuclei, ffuf, subfinder, sqlmap-lite) |
| `oob.listener` | Allocates interact.sh subdomain, streams hits back |
| `oracle.check` | Existing `_shared/proof-oracles.ts` |
| `cve.lookup` | Existing `cve-mapper` |
| `mutate.payload` | Existing UCB1 mutator |
| `chain.run` | Existing exploit-runtime |
| `findings.record` | Writes to DB with proof gate |
| `finish` | Marks session complete |

Each tool has a Zod `inputSchema`, compact serializable output, and destructive ones set `needsApproval: true`.

### Phase 5 — World model as agent memory

Replace ad-hoc `target_world_model.model` blob with structured slots the LLM sees every turn:
- `surface`: endpoints, params, forms, auth surfaces, tech stack, CVEs
- `beliefs`: WAF class, auth model, framework, redirect traps
- `attempts`: `{class, param, payload_family, outcome, confidence}[]` — feeds UCB1 and stops repeat attempts
- `hypotheses`: open questions with priority
- `budget`: credits/time remaining

Injected into every plan prompt; agent updates it via a dedicated `memory.write` tool.

### Phase 6 — UI streaming

- `BrainPanel` subscribes to `agent_events` for the active `session_id` via Realtime and renders the 3 lanes (Plan / Act / Observe) from event kinds directly.
- `ScanControl` calls a new `POST /sessions/:id/stop` on the runtime (SIGTERM to that agent).
- `Findings`, `OWASP`, `Diagnostics` keep reading their existing tables — the agent writes to them through tools, so they light up in real time.

### Phase 7 — Cutover

1. Ship runtime + Phase 2 tables behind a feature flag `USE_AGENT_RUNTIME`.
2. New scans start an `agent_session` instead of enqueueing 154 jobs.
3. Old `scan_jobs`/`phase-arbiter` cron kept alive 2 weeks for regressions, then deleted.
4. Delete: `phase-arbiter`, `phase-arbiter-tick`, `scan-orchestrator`, `scan-job-worker`, and every edge function that only existed to be enqueued.

---

## What survives from the current codebase

Kept and reused as tools/libraries: `_shared/proof-oracles.ts`, `_shared/exploit-runtime.ts`, `_shared/ai-mutator.ts`, `_shared/payloads-att.ts`, `_shared/cve-mapper.ts`, `_shared/world-model.ts`, `_shared/findings-writer.ts`, `injection-matrix`, `subdomain-enum`, `recon-engine`, `nvd-intel-sync`. UI shell, auth, credits, OWASP checklist table, findings table.

Retired: `phase-arbiter*`, `scan-orchestrator`, `scan-job-worker`, `enqueue-*`, the cron ticks, and every "queue then hope" flow.

---

## Timeline (rough)

- **Week 1:** Phase 1 (runtime host) + Phase 2 (tables) + skeleton loop that just calls `http.request` and writes events.
- **Week 2:** Phase 3 + 4: full tool surface incl. browser and oob; port oracles.
- **Week 3:** Phase 5 world model + Phase 6 UI streaming; parity scan on `networkbulls.com`.
- **Week 4:** Phase 7 cutover, delete dead code, tune prompts, add authenticated-scan tool.

---

## What I need from you before I start building

1. **Runtime host choice:** Fly.io Machine (my recommendation) or something else you already pay for?
2. **Extra LLM keys:** confirm we can use existing `LOVABLE_API_KEY` only, or also wire the OpenAI/Anthropic keys you mentioned earlier as first-class in the agent.
3. **Browser tool scope:** OK to run Playwright inside the runtime container (adds ~400MB image, needed for real DOM XSS / auth flows)?
4. **Cutover risk:** OK to leave old orchestrator running in parallel for 2 weeks, or hard-swap on day 1?

Answer those four and I'll start Phase 1 in the next turn.
