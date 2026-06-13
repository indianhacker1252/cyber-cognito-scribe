
# CyberScope Repair Plan — Addressing All 22 Defects

Goal: stop shipping disconnected modules. Every fix below is wired end-to-end (UI → orchestrator → engine → findings table → Neural Log → Report) and verified with a SQL/curl probe before I mark it done.

## Root cause of the previous failures
1. The UI "Start Scan" still dispatches to legacy monoliths (`scan-job-worker`, `param-bruteforce-xss`) instead of `mythos-orchestrator`, so 70% of the new engines never run.
2. Severity "hard drop" = LOW/MEDIUM/INFO findings skip the exploit + chain phase by an early `return` in `mythos-orchestrator/phase-router.ts`.
3. `?q=` is hardcoded in `param-bruteforce-xss` as the only fuzz target; payload list is the 4-item demo list (`<script>alert(1)</script>` etc.).
4. `recordFinding()` was written but only 3 of 14 engines call it → no `request_raw`/`response_raw` in DB → empty Request/Response tab.
5. Intel feed → template compiler exists but the cron that loads `intel_feeds` rows into `rag_exploits` is disabled.
6. Advisory pipeline marks CVE matches as `proof_tier='heuristic'`; nothing ever promotes to `exploited` so they're filtered out.
7. `LOVABLE_API_KEY` is set but `llm.ts` reads `Deno.env.get("LOVABLE_AI_KEY")` (typo) → every call 401 → fallback chain interprets as 402 → "credits exhausted".
8. Kali/Ollama worker proxy table (`external_infra_config`) exists, no edge function consumes it.

## Sprint (single implementation, in this order)

### A. Stop the bleeding (must land first)
- A1. Fix env name in `_shared/llm.ts` (`LOVABLE_AI_KEY` → `LOVABLE_API_KEY`). Add a startup self-test that pings the gateway once and writes result to `scan_logs`. → fixes #21.
- A2. Replace UI `startScan()` in `src/hooks/useScanLauncher.ts` so the only invocation is `supabase.functions.invoke('mythos-orchestrator', {...})`. Delete dead legacy calls. → fixes #19, #20.
- A3. In `mythos-orchestrator/phase-router.ts` remove the `if (severity < MEDIUM) return` short-circuit. Every finding enters exploit + chain phase; only the *reporter* filters by severity. → fixes #1.

### B. Real payloads & full param coverage
- B1. `param-bruteforce-xss`: enumerate parameters from (a) discovered_endpoints query string, (b) form inputs from katana crawl, (c) JSON body keys from response samples. Drop the `?q=` hardcode. → fixes #3.
- B2. Replace demo payload array with `seclists/Fuzzing/XSS/XSS-Jhaddix.txt` + the polyglot set already cloned in `/seclists`. Validate hits via reflected-context detector (attribute / JS / HTML / URL) — not substring match. → fixes #2.
- B3. Add WAF-adaptive prompt: when baseline 200 → mutated 403, append the obfuscation directive already drafted in `_shared/waf-detect.ts` to the next LLM mutation request.

### C. Evidence everywhere
- C1. Make `recordFinding()` the only insert path into `vulnerability_findings`. Add a migration that adds NOT NULL CHECK on `request_raw` and `response_raw` for new rows. → fixes "no request/response data".
- C2. Update the 11 remaining engines (`sqli-engine`, `ssrf-probe`, `idor-engine`, `auth-bypass`, `open-redirect`, `xxe`, `ssti`, `cmd-injection`, `path-traversal`, `cors-misconfig`, `jwt-attacks`) to use it.
- C3. `FindingDetailsDialog`: render Request/Response tabs from `request_raw`/`response_raw` with copy-as-curl.

### D. Intel & advisory
- D1. Enable the `intel-sync` cron (every 30 min). For each `intel_feeds` row with `status='new'`, compile to a `rag_exploits` template and mark `tested=false`. → fixes #4.
- D2. Run new templates against the active target before they become advisory-only. Only after a real probe matches do we insert a finding; CVE-only signals become `proof_tier='advisory'` (not `exploited`) and are excluded from "confirmed" counts. → fixes #5.

### E. Chaining
- E1. `mythos-chainer`: replace `{{base}}` placeholders with the actual `request_replays.id` reference. Each node stores the replay id, edges store the data-flow variable (`{{token_from_step_2}}`).
- E2. Acceptance: a 2-step chain (IDOR → priv-esc) must execute both steps with real cookies and store both raw req/resp. → fixes #22.

### F. Kali + Ollama bridge (the new capability you asked for)
- F1. New edge function `local-worker-proxy`: reads `external_infra_config` (worker URL + shared secret) and forwards tool jobs.
- F2. Kali side: a single `cyberscope-agent.py` installer (in `/scripts/kali-install.sh`) that:
   - registers the host with the worker secret
   - exposes nuclei, sqlmap, dalfox, katana, nikto, wpscan, gobuster, dirsearch, wafw00f, whatweb, sslscan, sslyze, testssl.sh, ffuf, amass, subfinder, httpx, naabu, masscan, nmap (covers your full list #18)
   - exposes a Playwright headless browser endpoint
   - exposes an Ollama proxy (`/ai/chat`) so the orchestrator can split LLM traffic: planning → Lovable AI, fuzzing/mutation → local Ollama. Both write `thought` rows tagged `source=lovable|ollama`, and a `co-learning` job feeds high-confidence Ollama hits back into Lovable AI's few-shot context.
- F3. UI: Settings → "Local Worker" panel showing connection status + tool capability list discovered from the agent.

### G. Verification (I will NOT claim done without these)
For each sprint I will run and paste output of:
- `psql -c "select count(*), proof_tier from vulnerability_findings where created_at > now() - interval '10 min' group by 2"` 
- `supabase functions logs mythos-orchestrator --tail 50`
- A live scan against `https://testphp.vulnweb.com` and the OWASP Juice Shop docker target.

## Files that will change (high level)
- supabase/functions/_shared/llm.ts, ai-credits.ts, recordFinding.ts, waf-detect.ts
- supabase/functions/mythos-orchestrator/* (phase-router, chainer integration)
- supabase/functions/param-bruteforce-xss/, sqli-engine/, ssrf-probe/, idor-engine/, auth-bypass/, open-redirect/, xxe/, ssti/, cmd-injection/, path-traversal/, cors-misconfig/, jwt-attacks/
- supabase/functions/intel-sync/ (enable cron), advisory-promoter/
- supabase/functions/local-worker-proxy/ (new)
- scripts/kali-install.sh, scripts/cyberscope-agent.py (new)
- src/hooks/useScanLauncher.ts
- src/components/FindingDetailsDialog.tsx
- src/pages/Settings/LocalWorker.tsx (new)
- migration: NOT NULL on request_raw/response_raw for new findings; `external_infra_config` columns for capability list

## What I need from you before I start
1. Confirm: split traffic = Lovable AI for planning/triage, Ollama for high-volume mutation/fuzzing? (cheapest, what you described)
2. Kali install target: a script you run manually on your box, or also a Docker image?
3. OK to enforce the NOT NULL request/response check on new findings (old rows untouched)?

Once you say go, I implement A→G in one pass and post the verification output for each.
