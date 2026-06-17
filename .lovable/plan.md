# Plan: Close the 12 Gaps and Make the Scanner Outperform XBOW

This plan addresses each of the 12 failures you listed. Every fix is scoped to existing edge functions/tables — no new infra. After this round, every signal produced anywhere in the pipeline funnels into the **exploit engine**, and the **debate / variant / fuzz** loops actually progress between iterations.

## Honest answer to your last question

**Can this tool currently find real, deep bugs and zero-days?** Not reliably yet — because of exactly the 12 gaps below. The detection engines exist, but signals are being dropped before they reach the exploit engine, the debate loop is double-deduping itself to zero, and the AI surface fails open instead of falling back. After this plan: yes — the tool will autonomously chain recon → fuzz → OOB → debate → exploit → kill-chain like XBOW, with the additional advantage of CVE-template + intel-feed grounding XBOW does not have.

---

## Section 1 — Critical pipeline plumbing (gaps 4, 5, 6, 7, 12)

The root cause across these is the same: detection engines write findings/issues to logs but never enqueue an `exploit` job. Fix once via a shared helper.

1. `**_shared/findings-writer.ts**` — extend `recordFinding()` to optionally enqueue a `scan_jobs` row of type `exploit` when `severity ∈ {high, critical}` OR `proof_tier ∈ {indicator, suspected}`. Returns the new job id so callers can log it.
2. `**auth-confusion-suite**` (gap 4) — for each of the 12 detected issues call `recordFinding({source:'auth-confusion', vuln_class, evidence, autoEnqueueExploit:true})`. Today they only `console.log`.
3. `**template-runner**` (gap 5) — wrap the existing 1-finding write with `autoEnqueueExploit:true` and add a `scan_logs` line so it shows in the summary.
4. `**kill-chain-graph**` (gap 6) — after chain synthesis, enqueue one `chain_exec` job per chain (currently chains are stored but never dispatched). `scan-job-worker` already routes `chain_exec` → `exploit-chain-runner`.
5. `**deep-asset-scan**` (gap 7) — for each discovered debug path enqueue an `exploit` job with `vuln_class='info-disclosure'` and a `fuzz` job with `vuln_class='ssrf'` targeting that path.
6. **Gap 12 verification** — once 2-5 are in place, every scan should log at least one `💀 Exploit Engine engaging` line; add an assertion in `mythos-orchestrator` that warns if iteration ends with `exploit_runs` count = 0.

## Section 2 — Debate dedup wipe (gap 1)

`mythos-debate` dedups by `vuln_class+url` across the whole run, so iterations 2-4 see every candidate as "already debated" → 0 TP/0 FP.

- Change dedup key to `vuln_class + url + payload_hash + iteration_bucket` (bucket = iteration index ÷ 2).
- If a debate's verdict is `inconclusive`, allow re-debate next iteration with a **new payload mutation** seeded by the previous transcript.
- Always insert a `mythos_debates` row with the verdict, even when no finding is escalated, so the UI shows progress.

## Section 3 — CVE template targeting (gaps 2, 3)

- **Tech-stack filter** — in `template-runner`, before running any intel-feed template, intersect `intel_feeds.affected_tech_stack` with `target_workspaces.detected_tech` (already populated by `recon-engine`). Skip with a `scan_logs` `info` row if no overlap. Allowlist generic classes (sqli, xss, ssrf, lfi) that aren't tech-bound.
- **Stop falling back to generic payloads** — only synthesize fallbacks when `extracted_payloads` is empty **and** the CVE class is in the allowlist above. Otherwise mark the template `skipped: no real payloads`.
- **Real payload extraction** — extend `intel-sync` to pull PoC blocks from HackerOne / Exploit-DB markdown using existing regex + an LLM extraction pass guarded by `checkCreditsAndFailFast`.

## Section 4 — Variant generator stagnation (gap 8)

`mythos-variant-gen` reuses the top-5 CVEs every iteration.

- Track a per-run `seen_cve_ids text[]` column on `mythos_runs` (add via migration).
- Each iteration: `WHERE id NOT IN seen_cve_ids ORDER BY cvss DESC LIMIT 5`, then append the new ids.
- When the pool is exhausted, switch strategy to **mutation of last iteration's failed payloads** instead of pulling new CVEs.

## Section 5 — Advanced fuzzing reach (gap 9)

Current Pro-Fuzzer only appends `?q=payload`. Upgrade:

- Parse each endpoint's `discovered_params` (already stored by recon) and fuzz **every param**, not just `q`.
- Add **POST form** (`application/x-www-form-urlencoded`) and **multipart** body fuzzing alongside the JSON-body pass that was just added.
- For endpoints whose `method` is POST/PUT, fuzz the request body fields harvested from prior responses or OpenAPI specs in `discovered_endpoints.spec`.
- Add a **reflected-XSS confirmer**: when payload appears in response body un-encoded, escalate directly via `recordFinding` with `proof_tier='exploited'`.

## Section 6 — OOB activation (gap 10)

OOB channel exists (`oob-collector`) but no probe injects it.

- Add `_shared/oob.ts` exporting `mintOobToken(runId, vulnClass)` → returns `https://<project>.functions.supabase.co/oob-collector/<token>` and a matching DNS-style subdomain token.
- Inject the token into every blind-class payload generated by `advanced-fuzzer`, `param-bruteforce-xss`, `auth-confusion-suite`, and `template-runner` (SSRF URLs, SQLi `LOAD_FILE`, XXE entity URLs, log4shell JNDI host, blind-XSS sinks).
- A new `oob-reaper` cron (5 min) joins `oob_callbacks` against pending tokens and, on hit, calls `recordFinding({proof_tier:'exploited', autoEnqueueExploit:true})`.

## Section 7 — AI credit fallback for recon (gap 11)

When `ai-surface-attacker` exhausts credits it currently returns 0 endpoints/params silently.

- Catch `AiCreditsExhaustedError` and fall back to a **heuristic surface ranker** (sort `discovered_endpoints` by: has-params desc, status 200/302 desc, contains `admin|api|login|upload|debug` desc, response length desc). Take top 30.
- Write a `scan_logs warn` row: "AI surface offline — using heuristic top-30."
- Continue the pipeline with those endpoints instead of stopping.

## Section 8 — Verification harness

After implementation, run an end-to-end self-test against `testphp.vulnweb.com`:

- Assert `exploit_runs` count ≥ 1, `mythos_debates` count ≥ 1 with non-null verdict, `oob_callbacks` count ≥ 1 (SSRF token), `vulnerability_findings.proof_tier='exploited'` count ≥ 1.
- If any assertion fails, the orchestrator writes a `scan_logs error` row naming the broken stage.

---

## Technical details (for the engineer-AI implementing this)

- **Migration**: `ALTER TABLE mythos_runs ADD COLUMN seen_cve_ids text[] DEFAULT '{}'::text[];` + grants already in place.
- **New shared helper signature**:
  ```ts
  recordFinding(db, payload, opts?: { autoEnqueueExploit?: boolean; runId?: string })
    → { findingId: string; exploitJobId?: string }
  ```
- **Enqueue exploit pattern** (used everywhere):
  ```ts
  await db.from("scan_jobs").insert({
    target_id, job_type: "exploit", priority: 8,
    payload: { findingId, vuln_class, url, payload, evidence },
    status: "queued", next_run_at: new Date().toISOString(),
  });
  ```
- **OOB token** — HMAC `runId|vulnClass|nonce` with `SUPABASE_SERVICE_ROLE_KEY` so collector can verify without DB read.
- **Debate dedup key** — `sha1(`${vuln_class}|${normalizeUrl(url)}|${sha1(payload)}|${Math.floor(iter/2)}`)`.
- **Tech-stack matcher** — case-insensitive substring both ways; treat empty `affected_tech_stack` as wildcard ONLY for the generic-class allowlist.

## Enhance everything  that is a breaker in this tool to beat xbow. Enhance everything if  needed.

Approve this and I will implement Sections 1-7 in a single build pass, then run the Section 8 self-test and report the assertion results.   