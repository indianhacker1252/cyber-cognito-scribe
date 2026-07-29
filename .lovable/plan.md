# Why this tool isn't performing like XBOW — honest gap analysis

You've asked "why doesn't this work like XBOW?" Here is the real answer, without spin.

## What XBOW actually is (so we're comparing to the right thing)

XBOW is a single **autonomous AI pentester** that:
1. Given a target, spawns a long-lived agent with a **shell + browser + HTTP client** as tools.
2. Uses a frontier LLM (Claude/GPT) as the *only* brain — no rule engine, no "phase arbiter", no 83-item checklist.
3. The agent **reads pages, writes payloads, executes them, reads responses, and iterates** — like a human, in one loop, for hours.
4. Reports only findings it **proved by exploitation** (screenshot, exfiltrated data, callback).

They win HackerOne benchmarks because the loop is: *LLM → tool → observation → LLM*, tight, stateful, and unbounded.

## What we actually built

We built a **workflow orchestrator that calls small deterministic scanners and asks the LLM to label results**. That is a fundamentally different architecture. Concretely:

| Layer | XBOW | Us |
|---|---|---|
| Brain | 1 LLM, long context, full trajectory | ~15 edge functions each doing one call |
| Tools | shell, headless browser, raw HTTP | pre-baked payload lists + regex matchers |
| State | one agent memory, grows over hours | 70 Postgres tables, no agent sees them all |
| Loop | LLM decides next action every step | `phase-arbiter` cron enqueues fixed phases |
| Proof | agent must demonstrate impact | trigger `enforce_finding_proof_gate` string-matches "root:" |
| Runtime | hours on one target | 50s per edge function, then dies |

## The five root causes

### 1. No real agent loop
`ai-strategist`, `agent-planner`, `mythos-agent` are **single-shot LLM calls** that emit a JSON plan, then die. XBOW's agent runs `while(!done) { llm.step() }` for hours. Our edge-function 50s ceiling makes that architecturally impossible — the loop has to live somewhere with no timeout (a worker VM, Durable Object, or a long-running Deno process on a real host).

### 2. LLM never touches the target
The LLM writes JSON like `{"technique":"sqli","param":"id"}`. A deterministic Deno function then fires a hard-coded payload from `payloads-att.ts` and regexes the response. The model **never sees the HTTP response**, so it can't adapt, can't spot weird behavior, can't chain. That's why findings feel "guess-passed" — because they literally are: regex-vs-payload, not model-vs-target.

### 3. No browser, no shell
Modern bugs (DOM XSS, SPA auth, CSRF-in-fetch, prototype pollution, most IDORs) require a real browser session. We have zero Playwright/Puppeteer in the runtime. `xss-reflection-promoter` was added to require DOM proof — and correctly rejects everything, because we never actually render a DOM. Same for shell: we can't run `sqlmap`, `ffuf`, `nuclei`, `httpx` — the tools human pentesters use.

### 4. Fragmented state, no memory
70 tables, and no single component reads more than 3–4 of them. `world-model` exists but is written by one function and read by almost nothing. The LLM in call N has no idea what the LLM in call N-1 saw. XBOW's agent has the entire trajectory in context.

### 5. Wrong success metric baked in
`enforce_finding_proof_gate` demotes anything without the substring `root:` or `CYBERSCOPE_PROVEN` in the response. That is a *heuristic for command injection on Linux*. It silently kills every legitimate finding of every other class. That's why the Findings tab is empty even on juicy targets.

## What the current codebase IS good for

Not nothing — it is a decent **recon + surface-mapper + checklist tracker**:
- Subdomain enum, JS analysis, endpoint discovery — works.
- OWASP checklist as a coverage dashboard — works.
- CVE version matching — works.
- Job queue + neural log UI — works.

It is not, and with edge-functions-only cannot become, an autonomous exploiter.

## The honest fix path

There are two directions. Pick one — doing both half-way is what got us here.

### Option A — Accept what we are: ship a great **assisted VAPT platform**
Stop pretending to be XBOW. Reposition as "AI-assisted recon + triage + reporting":
- Rip out `enforce_finding_proof_gate` (or scope it to command injection only).
- Delete `ai-strategist`, `agent-planner`, `mythos-*`, `chain-finder`, `exploit-runtime` — they don't earn their credit cost.
- Keep recon, checklist, CVE mapping, findings UI, report generator.
- Add **human-in-the-loop**: findings land as "candidate", auditor confirms in the Validation Workspace (already built).
- Small: ~1 week, delivers a working tool, kills the credit drain.

### Option B — Actually build XBOW: move the agent off edge functions
This is real work, weeks not days:
1. **Get a long-lived runtime.** A single Fly.io/Railway/Docker worker per scan, no 50s ceiling. Edge functions become thin RPC around it.
2. **Give the agent real tools:** headless Chromium (Playwright), a jailed shell with `curl/ffuf/nuclei/sqlmap`, raw TCP.
3. **One LLM, one loop, one context.** Claude Sonnet or GPT-5 with tool-calling, running `while(!done)`, full trajectory in context, checkpointed to Postgres every step.
4. **Kill the phase arbiter.** The agent decides what to do next. Period. No cron, no fan-out, no `PHASE_ORDER`.
5. **Proof = the agent says "I proved it and here's the artifact"** (screenshot, exfiltrated row, OOB callback). Trigger goes away.
6. Keep the current DB + UI as the *observer* — read-only view of what the agent did.

## Recommendation

**Option A this week, Option B as a separate v2 project.** The current architecture cannot be patched into XBOW — every "fix" of the last month has been adding another edge function to compensate for the fact that no single component owns the exploit loop. Stop patching, decide the shape.

## What I need from you

Which direction? Once you pick, I write a concrete implementation plan for *that* direction only — no more sweeping multi-pass changes across a codebase that's already fighting itself.
