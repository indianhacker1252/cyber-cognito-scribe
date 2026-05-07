# Plan — Phase 8 Zero-Day Engine + Black-Hat Methodology + Critical Bug Fixes

This is a large scope. I'll split it into **two waves** so you can verify each before moving on. Wave 1 fixes the broken things you reported and ships the highest-leverage Black-Hat methodology. Wave 2 ships the heavy Phase 8 modules.

---

## Wave 1 — Bug fixes + Black-Hat request/response engine (ship first)

### A. Fix what's broken right now
1. **Finding "Details" button** — `FindingDetailsDialog` only shows partial fields. Rewrite to show: full request, full response (with diff vs baseline), payload, parameter, proof_tier, hard_evidence, OOB callbacks, sandbox runs, related chains, remediation, CVSS vector, sensitive-redaction for non-admins.
2. **Proof Engine has no live logs** — `proof-engine` runs silently. Add `scan_logs` streaming inserts at every stage (OOB check → sandbox check → probe reflection → sensitive scan) so the Neural Log shows live output.
3. **AI agents not debating new findings** — `mythos-debate` only runs on demand. Hook it into `vuln-scanner` post-triage so every NEW high/critical or zero-day candidate auto-spawns a debate. Surface debates on the finding detail dialog.
4. **Sandbox not auto-running during scans** — currently manual. Add an auto-trigger in `vuln-scanner`: when a finding is created with confidence ≥ 60 and proof_tier = `signal`, fire `sandbox-exec` automatically.
5. **Exploit engine should behave like Metasploit** — create `exploit-engine` edge function: takes a finding, looks up matching exploit-db / nuclei / internal template, executes it via sandbox/worker, captures session/shell output, promotes proof_tier to `exploited` with full PoC.
6. **Mutation strategy on negative result** — extend `EvolutionaryFuzzer`/`SecListsMutator` so a "blocked/sanitized" response triggers WAF-bypass mutation (case toggling, encoding, comment injection, Unicode normalization, polyglot wrap) and retries up to N rounds.
7. **App testing broken after upload** — debug `app-package-scan` (likely storage path or worker dispatch). Re-test end to end.
8. **Realtime crash** — fix the `cannot add postgres_changes after subscribe()` runtime error in `NeuralLog` (channel must register listeners before `.subscribe()`).

### B. Black-Hat HTTP methodology engine
9. **Repeater + Intruder module** — new `request-repeater` edge function + UI panel on a finding: edit any part of the request (method, headers, body, params, cookies), re-fire, diff response, save promising mutations as new findings. This is the missing "Burp-style" workflow.
10. **Sensitive param/file/code sweep** — scan recon output and JS bundles for `password`, `token`, `api_key`, `secret`, `aws_`, `Bearer `, `.env`, `.git`, `.map`, source-map URLs, hardcoded endpoints, then auto-create findings.
11. **Exploit-DB ingestion** — new `exploitdb-sync` cron that pulls the latest Exploit-DB CSV, indexes into `rag_corpus` keyed by CVE/CWE, and lets `exploit-engine` resolve a finding → exploit code automatically.

---

## Wave 2 — Phase 8 Autonomous Zero-Day Engine

12. **Cloud Pivot Module (#26)** — `cloud-pivot` edge function. When SSRF returns AWS/GCP/Azure metadata creds, spawn pivot agent that calls STS `GetCallerIdentity`, lists S3, IAM, DynamoDB via REST (no boto3 in Deno — use AWS SigV4 directly). Reports "SSRF → Total Account Compromise" as a single chained finding.
13. **Polymorphic Payload Synthesis (#27)** — `chimera-forge` module. AI generates polyglots valid as JPEG+JS+PHP / JSON+YAML / SQL+XSS. Wires into upload-fuzzer and json-fuzzer.
14. **Autonomous Decompilation (#28)** — extend `app-package-scan` + add `wasm-decompile` and `sourcemap-rebuild`. When spider sees `.wasm`, `.map`, or `.apk`, route to decompiler, push reconstructed source into `rag_corpus`, run SAST.
15. **Side-Channel Timing Fuzzer (#29)** — `timing-oracle` edge function. Fires N baseline + N test requests, computes mean/stdev, flags ≥3σ deltas as username enumeration / blind boolean SQLi.
16. **Swarm / Hive-Mind (#30)** — design + scaffold only (full multi-region needs your infra). Add `swarm_state` table acting as Redis-style shared mind; extend docker worker reference to support multiple workers pulling tokens. Document scale-out in `deploy/README.md`.

### Database migrations
- `request_replays` (repeater history)
- `exploitdb_index` (CVE → exploit code)
- `cloud_pivot_results` (per-finding cloud takeover artifacts)
- `chimera_payloads`, `timing_oracle_runs`, `swarm_state`
- Add `auto_sandbox_enabled`, `auto_debate_enabled` flags to settings.

### Tech notes
- All new edge functions use `safeFetch`, hard 8s timeouts, always 200-OK pattern.
- All long jobs stream to `scan_logs` (Neural Log).
- Exploit-engine and cloud-pivot results marked `sensitive=true` → admin-only RLS.
- Mutation loop capped at 5 rounds to stay inside edge timeout.

### Risks
- Exploit-DB raw codes are dual-use — kept admin-only, never exposed to non-admin users.
- Cloud pivot is non-destructive read-only (List*/Get*/Describe* only). No writes/deletes.
- Swarm full multi-region requires user-supplied AWS regions; scaffolding only in this wave.

---

**Recommend approving Wave 1 first.** Once you confirm the broken things work + Repeater/Intruder + Exploit-DB feel right, I'll ship Wave 2 (Phase 8 modules) in the next turn.