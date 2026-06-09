
# XBOW/Mythos-Beating Chain Exploitation Engine

Goal: stop testing vulns in isolation. Build a **graph-based kill-chain engine** that combines weak signals (info leak + open redirect + IDOR) into provable critical exploits, plus 5 modern attack modules that go beyond SQLi/XSS.

## Part 1 — Kill-Chain Graph Engine (the core new capability)

Today `mythos-chainer` asks the LLM "propose chains" from a flat list — it misses non-obvious paths. Replace with a real **Attack Graph**:

- New table `attack_graph_nodes` (asset, endpoint, credential, token, capability, secret) and `attack_graph_edges` (precondition → postcondition, with required exploit).
- New edge function `kill-chain-graph`:
  1. Ingests every signal: findings, code_findings, oob_callbacks, leaked secrets, JWT decoded claims, discovered routes, auth_profiles, session_jars.
  2. Models each as a node with **STRIDE capability tags** (Spoof / Tamper / Repudiate / InfoDisclose / DoS / EoP).
  3. Runs **Dijkstra over exploit cost** to find shortest path from "anonymous attacker" → "admin RCE / PII dump / fund transfer".
  4. Emits ranked chains (≤6 steps) with concrete request sequences.
- Chains execute through existing `exploit-chain-runner` (already supports stateful cookie jar + var splicing).
- Each successful chain auto-promotes to `proof_tier='exploited'` and creates a HITL approval with the full request transcript.

## Part 2 — Five New Attack Modules (beyond SQLi/XSS)

Each is a new edge function wired into `mythos-orchestrator` and the graph engine.

### 1. `business-logic-fuzzer`
Catches the bugs scanners miss: price tampering, negative-quantity, coupon stacking, workflow skipping (POST step 3 without step 1/2), tenant-id swap, timestamp replay, integer-overflow on money fields. Uses semantic-diff against baseline + LLM judge for "did state change unexpectedly".

### 2. `auth-confusion-suite`
- **JWT**: alg=none, key confusion (RS→HS), kid traversal, embedded-jwk injection, weak HMAC crack.
- **OAuth**: redirect_uri loose-match, state-fixation, PKCE downgrade, scope upgrade via refresh, authorization-code replay.
- **SAML**: XML signature wrapping, comment truncation.
- **Session**: cookie tossing across subdomains, __Host- prefix bypass.

### 3. `prototype-pollution-and-gadgets`
Crawls JS bundles, identifies pollution sinks (`Object.assign`, `merge`, `_.set`), then loads a gadget chain database (jQuery, Lodash, Express) and synthesizes a payload that pivots pollution → XSS or RCE. Verifies in headless browser.

### 4. `desync-and-smuggling-v2`
Already have `smuggler`; extend with: HTTP/2 CRLF, h2c upgrade smuggling, TE.0/0.CL via CDNs (Cloudflare, Akamai, Fastly fingerprints), cache-key normalization attacks, websocket smuggling. Chains naturally with cache-poisoning → stored XSS.

### 5. `ai-surface-attacker` (new, nothing like it in XBOW today)
For targets that expose LLM features (chatbots, search, copilots):
- Indirect prompt injection via uploaded docs / web pages / email.
- System-prompt extraction, tool-call hijacking, RAG poisoning.
- Output-handler XSS (LLM responses rendered as HTML).
- Model-extraction probes.
Findings feed back into the graph as "agent compromise → arbitrary tool call".

## Part 3 — Zero-Day Discovery Loop

Replace pure-payload fuzzing with **differential + symbolic** discovery:

- `differential-oracle`: send the same request to N similar endpoints; flag any whose response shape diverges (catches access-control bugs no payload can find).
- `symbolic-param-explorer`: extract every param across the app, cluster by name/type, transplant params across endpoints (mass-assignment, hidden admin flags like `isAdmin=1`, `role=admin`, `debug=1`).
- `mutation-from-experience`: the existing `experience_vault` already stores winning payloads — wire it into `EvolutionaryFuzzer` so the GA seeds new mutations from real prior wins per-vuln-class.
- `variant-from-cve`: when `cve-version-matcher` flags a vulnerable library, `mythos-variant-gen` synthesizes a target-specific PoC instead of just reporting the CVE ID.

## Part 4 — Proof Quality (so reports actually get paid)

- All chain successes captured as **HAR + screen recording** via `headless-browser` (already deployed) + Playwright trace.
- `evidence_packages` row links: graph path, every request/response, video, AI narrative, CVSS, suggested patch from `mythos-patcher`.
- Strict gate: nothing reaches `bb-submit` without `proof_tier='exploited'` AND chain reproduced twice.

## Architecture

```text
recon → asset-scan → vuln-scanner ─┐
auth-deep → authz-grapher ─────────┤
mythos-codebase-ingest ────────────┼─► kill-chain-graph ─► exploit-chain-runner ─► evidence_packages ─► bb-submit
business-logic-fuzzer ─────────────┤        ▲                                          (HITL approval)
auth-confusion-suite ──────────────┤        │
proto-pollution-gadgets ───────────┤   experience_vault feedback
desync-smuggling-v2 ───────────────┤
ai-surface-attacker ───────────────┘
```

## Deliverables

1. Migration: `attack_graph_nodes`, `attack_graph_edges`, indexes, RLS + GRANTs.
2. Edge functions: `kill-chain-graph`, `business-logic-fuzzer`, `auth-confusion-suite`, `prototype-pollution-and-gadgets`, `desync-and-smuggling-v2`, `ai-surface-attacker`, `differential-oracle`, `symbolic-param-explorer`.
3. Orchestrator wiring: new phase `chain-synthesis` after triage; budget = 4 min per target on worker (no edge 50s limit).
4. UI: new `/kill-chains` page with graph visualisation (react-flow) showing nodes, exploited edges in red, ranked chains list with "Re-run" button.
5. Findings page: new chip `source=kill-chain` and `source=ai-surface`.

## Out of scope (this pass)

- Mobile/binary exploit chains.
- Network-layer attacks (we stay HTTP/HTTPS).
- Persistent C2; chain runner stays request/response.

## Confirm before I build

1. OK to add the `/kill-chains` graph page (uses react-flow, ~150KB)?
2. Should `ai-surface-attacker` run by default, or opt-in per target (some programs forbid AI-feature testing)?
3. Default chain depth cap 6 steps OK, or do you want unbounded with cost budget only?
