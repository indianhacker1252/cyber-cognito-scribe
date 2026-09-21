# CyberScope — Pro-Grade VAPT Rebuild Plan

## What's wrong today (honest diagnosis)

1. **Backend keeps pausing.** Lovable Cloud auto-pauses on inactivity → login fails, cron dies, MCP endpoint goes cold, agent sessions stall. Every other problem cascades from this.
2. **Two brains, neither finished.** ~120 stateless edge functions run one-shot scan phases *and* a long-lived VPS runtime agent runs the real ReAct loop. They don't share state; findings from one are invisible to the other.
3. **Findings pipeline leaks false positives.** `enforce_finding_proof_gate` trigger exists, but many modules still write findings without oracle-verified evidence (esp. XSS reflection, redirect, timing-based SQLi).
4. **Recon → exploit handoff is weak.** Subdomains and endpoints land in tables but aren't ranked, deduped, or fed back to the planner as a prioritised attack surface.
5. **Learning loop is stubbed.** `agent_experiences` + `agent_metrics` collect data; nothing reads them. `ai-mutator.ts` mentions UCB1 but isn't wired to a `technique_stats` table.
6. **No multi-context auth testing.** IDOR / BAC needs two authenticated sessions side-by-side. Runtime has one browser context and no `auth.compare` tool.
7. **Chains are shallow.** `chain.run` exists but the planner rarely picks >3-step chains — not enough seeded experiences, and no proof-carrying state between steps.
8. **Observability half-built.** BrainPanel shows events + a cost lane, but per-tool latency, proof-oracle pass/fail badges, and per-session token cost aren't surfaced.
9. **MCP endpoint deployed but under-used.** 4 tools exposed; no `run_scan`, `get_chain`, `explain_finding` — so ChatGPT/Claude connectors can read but not drive scans.
10. **Docs + install scripts exist but user hasn't cut over.** Self-host installer + migration script are ready; nothing runs until executed on the VPS.

## Fix plan (ordered by impact, do in this order)

### P0 — Kill the pause problem (unblocks everything)
- User runs `scripts/self-host-supabase.sh` on the VPS.
- Migrate data with `scripts/migrate-to-self-hosted.sh`.
- Point app `.env` + runtime agent at VPS.
- Result: 24/7 backend, cron runs, MCP stays hot.

### P1 — Unify the brain (kill the stateless/stateful split)
- Move heavy scan logic (`vuln-scanner`, `exploit-engine`, `ai-strategist`, `mythos-*`) *inside* the runtime agent as tools.
- Keep edge functions only for: auth callbacks, MCP, lightweight webhooks, cron triggers.
- Every finding flows through **one** writer (`findings-writer.ts`) with mandatory oracle proof.

### P2 — Proof-gate everything (zero-FP goal)
- Every insert into `vulnerability_findings` must carry an oracle verdict row in `proof_evidence`.
- Add missing oracles: DOM XSS (headless capture), SSTI (arithmetic marker), NoSQL injection (operator-diff), race-condition (parallel replay).
- Trigger blocks inserts lacking `proof_evidence.verdict='confirmed'`.

### P3 — Ranked attack surface
- New table `attack_surface(target_id, url, method, params, tech, priority_score, last_probed)`.
- Recon writes here; planner reads top-N by score each iteration.
- Score = tech-stack risk × auth-required × param-count × freshness.

### P4 — Real multi-context auth testing
- Add `auth.login(context_name, creds)` and `auth.compare(url, ctxA, ctxB)` tools in runtime.
- Two named Playwright contexts per session.
- Enables real IDOR / BAC / privilege-escalation proofs.

### P5 — Close the learning loop
- Create `technique_stats(technique, target_class, tries, wins, ucb1_score)` + `bench_runs(ts, precision, recall)`.
- Wire `ai-mutator.ts` UCB1 to read `technique_stats`.
- Nightly bench run (Juice Shop / DVWA) writes precision/recall delta.

### P6 — Deep chains
- Seed 20 synthetic `agent_experiences` from known kill-chains (login → IDOR → SSRF → RCE, etc.).
- `chain.run` carries cookie jar + extracted tokens between steps.
- Planner rewarded for chain depth in critic score.

### P7 — MCP as a control surface
- Add tools: `run_scan(target)`, `get_chain(id)`, `explain_finding(id)`, `list_running_agents`.
- Lets ChatGPT/Claude connectors *drive* the tool, not just read it.

### P8 — Observability polish
- BrainPanel: per-tool latency histogram, proof-oracle pass/fail badges, per-session $ cost.
- Diagnostics page: live queue depth, cron heartbeat, oracle FP rate.

## Success criteria (how we know we beat XBOW/Mythos)
- 24h unattended scan on `juice-shop.herokuapp.com` finds ≥ 90% of OWASP Top 10 with < 5% FP rate.
- ≥ 3 multi-step chains (≥ 4 steps each) confirmed with cookie/token replay.
- BrainPanel shows every finding traceable to a planner trace + oracle verdict.
- MCP: Claude can start a scan, wait for it, and explain a finding, end-to-end.

## What I need from you next
- **Now:** run P0 (VPS install + migrate) and paste VPS IP + `/opt/supabase/CREDENTIALS.txt` contents. That unblocks 1–8.
- **After P0:** approve this plan and I'll execute P1 → P8 in sequence, each as its own reviewable change.
