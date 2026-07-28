# SPECTER / CyberScope — Project Charter & Working Plan

## 1. What we are building

An **autonomous VAPT (Vulnerability Assessment & Penetration Testing) engine** — a black-box security scanner that takes a target domain and, with no human in the loop, performs the same depth of work a skilled human pentester would: recon → attack-surface mapping → hypothesis-driven exploitation → proof-tiered confirmation → chained-impact reporting.

**Explicit goal:** match and exceed the practical output quality of XBow and Mythos-class autonomous pentesting agents — not by copying their internals, but by fixing our own pipeline until it reliably produces the same class of outcome: **confirmed, chained, low-false-positive findings on real targets**, not just scan logs full of activity.

**Non-goal for now:** source-code/white-box analysis. Everything in this plan is black-box/DAST.

---

## 2. Core design philosophy

Every fix must respect these principles:

1. **A finding is only real if it is proven, not just probed.** Every vulnerability class needs a deterministic proof condition: error signature, reflected marker absent from baseline, timing delta, OOB callback, replay determinism, or equivalent proof. Never accept a bare “we sent a payload and got a response.”
2. **Silence is worse than a false positive, but both are failures.** The system must not go quiet when it cannot reach a target or when AI credits run out. It must say so loudly in logs, not return empty arrays that look like clean targets.
3. **Every module that exists must be reachable.** A detector that nothing calls is functionally the same as no detector. Wiring is part of correctness.
4. **Scheme/protocol correctness is foundational.** If a URL is stored or requested with the wrong scheme, everything downstream can fail silently and look like “target has no bugs” instead of “we never connected.”
5. **Concurrency must be safe.** Any job/queue system must claim work atomically. Duplicate execution wastes resources, corrupts results, and can burn paid AI credits twice.

---

## 3. Current black-box/DAST architecture

```text
recon-engine ─┬─> subdomain-enum ─> recon-juicy / recon-deep (per-host fan-out)
              ├─> spider / headless-browser (SPA fallback)
              ├─> discovered_endpoints, discovered_forms, scan_assets
              └─> fans out follow-up jobs via scan-job-worker

scan-job-worker (central dispatcher — job queue, atomic claim, JOB_ROUTES map)
   │
   ├─ vuln_scan ──> vuln-scanner (OWASP-10 matrix + advanced modules)
   ├─ fuzz ────────> advanced-fuzzer (CVE templates + grammar payloads + AI Brain round)
   ├─ matrix_fuzz ─> matrix-fuzzer (method × param × location matrix, auth-aware)
   ├─ jwt_attack ──> auth-confusion-suite
   ├─ auth_deep ───> auth-deep (weak-secret brute, JWK injection, OAuth)
   ├─ authz_graph ─> authz-grapher (IDOR/BOLA; needs dual auth profiles)
   ├─ ssrf_deep ───> ssrf-deep (OOB-confirmed blind SSRF)
   ├─ graphql ─────> graphql-attack (self-discovers endpoint)
   ├─ json_fuzz ───> json-fuzzer (self-discovers JSON POST endpoint)
   ├─ cve/cve_exploit ─> cve-version-matcher / cve-to-exploit
   ├─ route_fingerprint ─> route-fingerprint (per-endpoint CVE-by-version)
   └─ template ────> template-runner (Nuclei-style OWASP templates, WAF-aware)

findings-writer (shared) — every module funnels confirmed findings through here
   ├─> ai-confirm-gate (honeypot detection + AI verdict + deterministic fallback)
   ├─> queues proof job ──> proof-engine (OOB/sandbox/reflection promotion)
   └─> queues triple_verify job ──> triple-verify (rebaseline drift + replay determinism)

mythos-orchestrator — phase state machine:
   asset-scan → template-runner → advanced-modules → chain iterations
   (chainer / variant-gen / debate) → kill-chain-synthesis → patch

mythos-debate — two-agent TP/FP debate + structured AI next-step logging
mythos-chainer — pathfinding over confirmed findings toward goal states (RCE, data exfil, ATO)
kill-chain-graph — graph-cost based chaining that feeds exploit-chain-runner
phase-arbiter — auto-stall detection plus diagnose/resume actions
nvd-intel-sync — hourly CVE relevance matching plus manual resync-target action
findings-audit-report — dedup_key/group_key collision audit, downloadable
```

---

## 4. Confirmed-fixed issues to protect from regression

Before editing any file in this section, check for its known fix marker or explanatory code comment. If the marker is gone, flag it as a regression before making new changes.

| # | Bug | File | Fixed how |
|---|---|---|---|
| 1 | RAG vault `_normalized` undefined var, runtime crash | `supabase/functions/_shared/exploit-guards.ts` | Defined before use |
| 2 | CVE template `probeUrl` out-of-scope | `supabase/functions/advanced-fuzzer/index.ts` | Moved fetch inside parameter loop |
| 3 | `vuln-scanner`, `authz-grapher`, `triple-verify`, `json-fuzzer`, `auth-deep`, and `route-fingerprint` were not wired to job routes | `supabase/functions/scan-job-worker/index.ts` | Added routes and fan-out queue entries |
| 4 | `proof-engine` never queued | `supabase/functions/_shared/findings-writer.ts` | Queues a `proof` job on every finding |
| 5 | Empty exploit chains falsely reported as `CONFIRMED (0 steps)` | `supabase/functions/exploit-chain-runner/index.ts` | Guard on `stepList.length === 0` |
| 6 | `confirmFinding()` silently dropped findings when AI was unavailable | `supabase/functions/_shared/ai-confirm-gate.ts` | Deterministic-proof fallback to manual review |
| 7 | `race-runner` `raced` was always false without caller-supplied regex | `supabase/functions/race-runner/index.ts` | Added status-code fallback signal |
| 8 | JWT bypass test had a false-positive path by testing against public homepage | `supabase/functions/auth-confusion-suite/index.ts` | Baseline must reject garbage token gate |
| 9 | `hypothesis-test-runner` had generic proof-word false positives and no baseline | `supabase/functions/hypothesis-test-runner/index.ts` | Baseline diff plus generic-word filter |
| 10 | `ai-strategist` allowed guessable proof strings | `supabase/functions/ai-strategist/index.ts` | Nonce-based unique proof requirement |
| 11 | `advanced-detectors` crashed on bare domains with `Invalid URL` | `supabase/functions/advanced-detectors/index.ts` | Added `normalizeUrl` / `resolveEndpointUrl` handling |
| 12 | Open redirects were not detected as true positives | `supabase/functions/mythos-debate/index.ts` | Added `isOpenRedirect` check and `locationHeader` capture |
| 13 | WAF bypass profile was computed but unused by fuzzers | `supabase/functions/_shared/waf-detect.ts`, `supabase/functions/advanced-fuzzer/index.ts` | Added `loadWafBypassProfile` / `wafWrap` use |
| 14 | NVD CVE jobs were re-queued every hour without deduplication | `supabase/functions/nvd-intel-sync/index.ts` | Existing-job check before insert |
| 15 | `mythos-variant-gen` double-declared `const body` and discarded redirect results | `supabase/functions/mythos-variant-gen/index.ts` | Unified `finalBody` / `finalStatus` path |
| 16 | Scheme bug from hardcoded `https://` in multiple URL-insertion paths | `supabase/functions/recon-engine/index.ts` | Routed URL insertion through `normalizeUrl(url, SCHEME)` |
| 17 | `classifyParameters` tested zero vuln classes when parameter name was not in lookup table | `supabase/functions/vuln-scanner/index.ts` | Universal RXSS + SQLi baseline merged with name hints |
| 18 | SQL-error signature list had no Microsoft SQL Server patterns | `supabase/functions/vuln-scanner/index.ts` | Added MSSQL / ASP.NET / ADO signatures |
| 19 | `runPassiveChecks` hardcoded HTTPS and silently returned empty on HTTP-only targets | `supabase/functions/vuln-scanner/index.ts` | Added HTTPS-to-HTTP fallback |
| 20 | OWASP checklist evidence upgrading was limited to a small hardcoded key set | `supabase/functions/scan-job-worker/index.ts` | Extended `JOB_TO_MODULES` and added evidence-upgrade logic |
| 21 | `mythos-chainer` silently skipped on AI-credit exhaustion and had an off-by-one signal threshold | `supabase/functions/mythos-chainer/index.ts` | Added explicit log line and fixed threshold |
| 22 | Job-claim race condition used SELECT-then-UPDATE without atomicity | `supabase/functions/scan-job-worker/index.ts` | Atomic `UPDATE ... WHERE status = 'queued' ... SELECT` claim |

---

## 5. Known open gaps

| Gap | Why it matters | Status |
|---|---|---|
| No dual-auth-profile UI/capture flow | `bac-tester`, `authz-grapher`, and parts of `auth-deep` are structurally starved, so IDOR/BOLA testing is limited | **Blocking; frontend work required** |
| `oob_chain` detector re-waits full timeout after repeated misses on the same target | Pure time/cost waste at scale | Flagged, not fixed |
| `matrix-fuzzer` can report `0 probes, 0 methods, 0 params` despite fan-out across real assets | Could be data starvation or logic bug | Needs live-log investigation |
| `default.aspx`-as-hostname artifact was observed in one log | Likely same class as prior scheme/URL insertion issues, but exact insertion path is unknown | Needs direct `scan_assets` query |
| No live-run verification of the fix batch | Static analysis is not enough to prove scanner correctness | **Top priority** |
| Multi-step chain depth has not been observed in real logs | This is the core differentiator between a scanner and an autonomous pentest agent | Wait until confirmed findings exist |

---

## 6. Current verification gate

Do not skip these steps:

1. Deploy every protected fix in section 4.
2. Run one clean scan against the known-vulnerable control target `testaspnet.vulnweb.com`.
3. Bring back all three artifacts together:
   - scan log,
   - `vulnerability_findings` table contents, even if empty,
   - `findings-audit-report` output.
4. Only after at least one real confirmed finding lands, move to chain-depth and authenticated-testing work.

---

## 7. Future scope

- Dual-auth-profile capture UI to unlock IDOR/BOLA/JWT-full-suite testing.
- White-box/source-ingest mode. `mythos-codebase-ingest` already exists as a stub, but source-code analysis is parked for now.
- `oob_chain` result caching per target to stop repeated full-timeout waits.
- Public benchmark methodology, such as OWASP Benchmark or CyberSecEval-style scoring, once findings are reliably confirmed.

---

## 8. Rules of engagement for future sessions

1. **Always diff any uploaded zip against the last known-good state first.** Confirm what survived, what reverted, and what is genuinely new before writing code.
2. **Use full-file replacement when handing back fixes.** Avoid partial snippets that require manual merging and can cause fixes to silently vanish.
3. **Give one honest status update per session:** what is live-verified, what is reasoned-but-untested, and what remains open.
4. **Do not add new capability work until the current fix batch is live-verified.** Depth work, authenticated testing, and benchmarking wait behind the verification gate.
