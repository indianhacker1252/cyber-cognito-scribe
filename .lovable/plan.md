# CyberScope recovery plan — make the scanner actually work

## Current diagnosis: why it feels broken

This is not a "payload quality" problem first. The implementation is fragmented: many advanced engines exist, but the main user scan path does **not** reliably route through the new resumable orchestrator, external worker, local AI, or chain executor.

### Evidence from code + logs

| Area | What exists | What is broken |
|---|---|---|
| Neural Log errors | `log_type='error'` exists in DB/types/UI | Recent logs still show old cascade: `Agent A/B: [A] LLM error 402`, `Executed: [B] LLM error 402`, and `Mutation rejected (class=bllmerror)` because the active path still uses old callers. |
| Main scan button | `Targets.tsx` calls `recon-engine`, `advanced-fuzzer`, drift, then optionally `mythos-agent` | It does **not** start the resumable `mythos-orchestrator`; it still fires older `mythos-agent` in places. |
| Resumable orchestrator | `mythos-orchestrator` supports phases: asset scan, templates, advanced modules, chain, variant, debate, kill-chain synthesis | It only runs when a `scan_jobs` row of `job_type='mythos_step'` exists. Recent jobs show only `drift_canary` and `exploit`; no `mythos_step`, so the orchestrator is not actually driving scans. |
| Scan worker | `scan-job-worker` routes `mythos_step → mythos-orchestrator`, `mutate → request-mutator` | It only picks `status='queued'`; no global pause/credit handling at worker level, no Kali/local tool routing jobs. |
| Chaining UI | `KillChains.tsx` can build graph and show chains | `Execute` creates dummy steps with `url: "{{base}}"`, so chain execution cannot perform real attack paths. |
| Chain executor | `exploit-chain-runner` can do multi-step stateful requests with extraction/cookie jar | It needs real steps; current KillChains UI does not translate graph steps into executable HTTP requests. |
| Request mutator | `request-mutator` parses captured raw HTTP requests and mutates them | It only works if findings have `request_raw`; many older/direct insert paths still insert `hard_evidence` only, not raw request/response. |
| External worker | Docker reference has nuclei, ffuf, sqlmap, Playwright, sandbox, APK scan | Dispatcher only supports `/run` for `nuclei|ffuf|sqlmap`; Playwright/APK/sandbox are not unified into the worker dispatcher or orchestrator. |
| Ollama/local AI | Settings page has an Ollama provider field | `_shared/llm.ts` never reads `ai_provider_config`; no Ollama provider is actually called. |
| Kali tools | Docker reference is Debian-based with a few tools | There is no Kali install profile, no tool capability handshake, no automatic tool planner, no result parser back into findings. |

## Root cause

The tool currently has **feature islands**:

1. Advanced modules were added as standalone edge functions.
2. The user-facing scan starts older/direct paths.
3. The newer orchestrator is resumable but not the default entry point.
4. Local AI/Ollama is configured in UI but not used by the LLM router.
5. Kali/browser tools exist in a reference worker but are not part of the scanner decision loop.
6. Kill-chain execution uses placeholder URLs instead of verified captured requests.

So the next implementation must be wiring-first, not "add another scanner".

---

# Phase 0 — stop fake success and expose wiring state

Goal: if a module is not connected, the UI must say so instead of pretending.

## 0.1 Scanner capability matrix

Add a `scanner_capabilities` health view in System Health:

- Lovable AI: available / credits exhausted / last error
- Ollama: configured / reachable / model list
- Kali worker: configured / reachable / tools detected
- Browser automation: available / missing
- OOB callback collector: available
- Orchestrator: last run / current phase / queued jobs
- Kill-chain graph: nodes / edges / executable chains

## 0.2 Wiring audit logs

At scan start, write one Neural Log banner:

```text
🧭 Pipeline selected: orchestrator=true, local_ai=false, kali_worker=false, browser=false, oob=true
```

No more silent fallback.

---

# Phase 1 — make the real orchestrator the only scan pipeline

## 1.1 Replace old scan trigger

Change the main scan action to call:

```ts
supabase.functions.invoke("mythos-orchestrator", {
  body: { targetId, triggerType: "manual", maxIterations: 5 }
})
```

or insert the first `scan_jobs` row directly:

```json
{ "job_type": "mythos_step", "payload": { "nextPhase": "init" } }
```

## 1.2 Stop using `mythos-agent` as default

`mythos-agent` is the old monolithic 50s path. Keep it only as legacy/manual fallback. Replace post-scan calls in `vuln-scanner` and `Targets.tsx` with `mythos-orchestrator`.

## 1.3 Worker-managed scan phases

Every long task becomes a queued `scan_jobs` step:

1. `recon`
2. `template`
3. `advanced_modules`
4. `browser_probe`
5. `kali_tool_probe`
6. `variant_gen`
7. `debate_verify`
8. `request_mutate`
9. `kill_chain_graph`
10. `chain_execute_readonly`
11. `proof_package`

## 1.4 Verification target

After this phase, recent jobs must show:

```sql
select job_type,status,count(*) from scan_jobs group by 1,2;
-- must include mythos_step/template/browser/kali/mutate/chain rows
```

---

# Phase 2 — fix AI routing: Lovable AI + Ollama learn from each other

## 2.1 Implement a real AI router

Replace hardcoded raw AI calls with one router:

```ts
llmCall({ role: "payload_planner", targetId, messages })
```

Router order:

1. Lovable AI — strong reasoning / orchestrator planning.
2. Ollama — local payload mutation, classification, tool-output summarization.
3. Direct provider keys — optional fallback if configured.
4. No-AI deterministic mode — templates + tools only, no fake payloads.

## 2.2 Add Ollama provider to edge and local worker

Cloud edge functions cannot reach `localhost:11434` on the user's machine. Therefore Ollama must run through the local Kali worker:

```text
CyberScope backend → Kali worker /ai → Ollama localhost:11434
```

Worker endpoints:

- `GET /health` returns `ollama: true`, models, tools.
- `POST /ai` calls Ollama `/api/chat`.
- `POST /learn` stores successful payloads/tool outputs locally and returns embeddings/tags.

## 2.3 Co-learning loop

For each candidate:

1. Lovable AI proposes attack class + reasoning.
2. Ollama mutates locally using target-specific context and Kali output.
3. Skeptic verifier rejects non-reproducible or unsafe payloads.
4. Executed request/response becomes feedback.
5. Both cloud and local memory update target strategy weights.

## 2.4 No more LLM-error payloads

Global guard before **any** HTTP request:

```ts
reject payload if /LLM error|bllmerror|credits exhausted|^\[[AB]\]/i
```

This guard must exist in:

- `mythos-debate`
- `mythos-variant-gen`
- `exploit-engine`
- `request-mutator`
- `vapt-chat`
- `Coordinator.ts`
- `EvolutionaryFuzzer.ts`

---

# Phase 3 — Kali Linux local worker

## 3.1 Installation target

Support this flow:

```bash
curl -fsSL https://.../install-cyberscope-kali.sh | bash
cyberscope-worker enroll --backend <backend-url> --token <token>
cyberscope-worker start
```

## 3.2 Worker capabilities

The Kali worker should expose:

| Endpoint | Purpose |
|---|---|
| `GET /health` | Tool inventory + Ollama status |
| `POST /run` | Run approved CLI tools |
| `POST /browser` | Playwright/Chromium workflows |
| `POST /ai` | Local Ollama chat/mutation/classification |
| `POST /sandbox` | Read-only PoC execution |
| `POST /parse` | Convert raw tool output into structured findings |

## 3.3 Tool set

Baseline Kali profile:

- `nuclei` — CVE/templates
- `httpx` — probing/tech detection
- `katana` — crawling
- `subfinder` — subdomains when in scope
- `dnsx` — DNS validation
- `ffuf` — content discovery
- `dalfox` — XSS with DOM/reflection verification
- `sqlmap` — only read-only, risk 1, level 1/2, HITL for anything aggressive
- `nmap` — safe service/version detection only
- `wappalyzer`/`whatweb` — tech fingerprinting
- `playwright` — browser execution, DOM sinks, postMessage, hidden XHR discovery
- `jq`, `curl`, `python3` — controlled scripts

Safety rules remain non-negotiable:

- No destructive flags.
- No brute force unless user authorizes scope and rate.
- HIGH/CRITICAL exploit chains require HITL before aggressive proof.
- Default PoC mode is read-only.

## 3.4 Tool planner

The orchestrator chooses tools based on signals:

| Signal | Tool action |
|---|---|
| Many JS files / SPA | Playwright + DOM sink tracer |
| WAF detected | Slow throttle + encoded payload family + dalfox WAF mode |
| GraphQL endpoint | introspection safe probe + authz grapher |
| Login/session available | authz grapher + IDOR diff tests |
| 403 admin routes | header bypass + verb tamper + ffuf low-rate |
| Reflected parameter | browser proof + dalfox |
| Version fingerprint | nuclei CVE + live-cve-runner |
| Blind vectors | OOB canary token injection |

---

# Phase 4 — real request/response capture everywhere

## 4.1 One finding writer only

All scanners must call `recordFinding()` and include:

- `request_raw`
- `response_raw`
- `response_diff`
- `source`
- `proof_tier`
- `replay_id`

Direct inserts into `vulnerability_findings` must be replaced.

## 4.2 HAR capture

Browser and Kali runs must attach:

- HAR or request list
- final URL
- status
- headers
- body snippet
- screenshot for browser proof

## 4.3 Mutation seed policy

`request-mutator` should not wait only for HIGH/CRITICAL. It should run on:

- confirmed findings
- interesting 403/401 routes
- auth endpoints
- endpoints with ID-like parameters
- endpoints with JSON bodies
- endpoints with role/user/account fields

---

# Phase 5 — make kill-chain execution real

## 5.1 Build chains from verified requests

`kill-chain-graph` must store chain steps as executable request references, not labels.

Each step should point to:

- `finding_id`
- `request_replay_id`
- extraction rules
- expected proof condition
- rollback/read-only safety note

## 5.2 Fix KillChains UI execution

Current UI sends placeholder steps:

```ts
{ name: "step-0", method: "GET", url: "{{base}}" }
```

Replace with real `step_plan` compiled from stored request/replay rows.

## 5.3 Chain proof tiers

| Tier | Meaning |
|---|---|
| `theoretical` | graph says path may exist |
| `replayable` | every step has captured request/response |
| `verified` | each step reproduced independently |
| `chained` | end-to-end chain executed read-only |
| `reportable` | PoC + evidence package generated |

Only `verified` or above should be shown as reportable.

---

# Phase 6 — beyond XBOW-style deep bug hunting

## 6.1 Differential semantic diffing

Not just status/length. Parse:

- HTML DOM structure
- JSON keys and auth-sensitive fields
- redirects and cookies
- role/user/account identifiers

Promote bugs like:

- same 200 status, but new PII fields appear
- same page length, but account ID changed
- hidden API response reveals admin-only fields

## 6.2 Behavioural canaries

Inject unique HMAC canaries into:

- headers
- JSON values
- URL params
- template strings
- SSRF URLs
- XML payloads
- log-style payloads

OOB callback = deterministic proof.

## 6.3 Payload genome

Persist target-specific payload learning:

- payload
- mutation family
- WAF response
- reward score
- generation
- source AI/tool

Next scan starts with proven families, not generic `<script>alert(1)</script>`.

## 6.4 Auth/session intelligence

Use `auth_profiles` and `session_jars` to run:

- role confusion
- horizontal IDOR
- vertical privilege bypass
- replay after logout
- JWT claim mutation
- CSRF/state desync

## 6.5 Browser-native bug hunting

Use Playwright for:

- DOM XSS sink tracing
- postMessage origin abuse
- client-side route discovery
- hidden API harvesting
- CSP bypass signals
- service worker/cache poisoning signals

---

# Phase 7 — exact implementation order

## Sprint 1: wiring repair

1. Main scan starts `mythos-orchestrator`, not `mythos-agent`.
2. `vuln-scanner` post-scan uses orchestrator job, not monolithic Mythos.
3. `scan-job-worker` adds explicit routes for `kali_tool`, `browser_tool`, `ollama_ai`, `kill_chain_execute`.
4. System Health shows pipeline capability matrix.
5. Neural Log shows pipeline banner and missing capability warnings.

## Sprint 2: local Kali/Ollama worker

1. Add Kali worker install script.
2. Add `/ai`, `/browser`, `/parse`, enhanced `/health` to worker.
3. Extend `docker-worker-dispatch` into `external-tool-dispatch` supporting tool classes, not only nuclei/ffuf/sqlmap.
4. Wire Settings health check to validate worker + Ollama.

## Sprint 3: evidence correctness

1. Replace direct finding inserts with `recordFinding()` in template-runner, zeroday-engine, advanced modules.
2. Capture raw request/response and replay rows for every interesting probe.
3. Run `request-mutator` automatically on replayable seeds, not only HIGH/CRITICAL.

## Sprint 4: chain execution

1. Modify `kill-chain-graph` to generate executable step plans.
2. Fix `KillChains.tsx` to pass real steps.
3. Add proof tier state machine.
4. Generate evidence package after read-only end-to-end chain.

## Sprint 5: learning loop

1. Add `payload_genome` table.
2. Add `target_brain` JSON to target workspace.
3. Store Lovable AI + Ollama decisions and outcomes.
4. Seed every future scan from target-specific winning payload families.

---

# Acceptance tests

## Scan pipeline

- Starting a scan creates `mythos_step` jobs.
- Neural Log shows phase transitions.
- No new log lines contain `LLM error 402` as a payload.
- No `bllmerror` mutation rejections on new scans.

## Kali/Ollama

- Worker health shows tools and Ollama models.
- A scan with worker active runs at least one Kali tool when signal matches.
- Tool output becomes structured findings or explicit "no finding" evidence.

## Evidence

- Every reportable finding has `request_raw` and `response_raw`.
- Findings UI displays request/response data.
- Re-run mutation button has seeds and produces replay logs.

## Chaining

- Kill-chain page shows only executable chains as runnable.
- Execute uses real captured requests, not `{{base}}`.
- Chain result includes step-by-step request/response proof.

---

# Immediate conclusion

Before adding more "advanced" features, the scanner must be rebuilt around one pipeline:

```text
UI scan → mythos-orchestrator → scan_jobs → AI router → Kali/Ollama worker + Cloud AI → evidence writer → mutator → kill-chain graph → chain executor → proof package
```

That is the path that can become better than XBOW/Mythos-style generic scanning. The current project already has many pieces, but they are not wired into that path consistently.