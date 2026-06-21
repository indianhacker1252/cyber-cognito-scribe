# Why we still lose to XBOW — and the plan to close it

## The honest gaps (what is actually broken today)

1. **Scan scope collapses to the apex host.**
   `recon-engine` discovers subdomains and writes them to `discovered_endpoints`, but `mythos-orchestrator` / `advanced-fuzzer` / `template-runner` iterate only over `target_workspaces.url` (the apex). The 5 subdomains we found are never attacked. Result: 80% of the real attack surface is ignored.

2. **Parameter coverage is shallow.**
   Fuzzer picks the first 1–2 query keys (often just `q`) and skips:
   - all other `discovered_endpoints.parameters` keys,
   - JSON body keys harvested by `js-deep-expand`,
   - path segments (`/users/{id}` → IDOR),
   - headers (`X-Forwarded-For`, `Referer`, `Origin`),
   - cookies.
   So 90% of injectable sinks are never touched.

3. **HTML forms & file uploads are not exercised.**
   `dom-fuzz` finds `<form>` and `<input type=file>` elements, but no module submits them with attack payloads, multi-part bodies, polyglot files (SVG-XSS, PHP-in-JPEG, zip-slip, XXE-DOCX). Upload-fuzzer exists but is **not enqueued** by the orchestrator.

4. **HTTP method matrix is GET-only.**
   `MethodExpansion.ts` probes alternative methods for *baseline diffing* but never re-runs the **payload battery** under PUT/PATCH/DELETE/OPTIONS/TRACE. So a write-side SQLi/SSRF on a PUT endpoint is invisible to us.

5. **Chain-finder fires once and dies.**
   `chain-finder` proposes one next step and queues one synthetic finding. There is no **loop** — after step 2 succeeds nothing requeues chain-finder, so kill-chains stop at depth 2 instead of going apex→subdomain→IDOR→privesc→RCE.

6. **No per-asset job sharding.**
   Worker treats "scan target X" as one job. XBOW shards per (subdomain × endpoint × method × param) and runs them in parallel with a budget. We serialize everything behind one queue entry.

7. **Forms harvested ≠ forms tested.**
   `discovered_endpoints` stores form action + fields, but `advanced-fuzzer` only fuzzes URL query, never POSTs the form body with payloads in every field.

---

## The plan (one decisive implementation pass)

### Phase 1 — Fan out the scope (kills gap #1, #6)

1. New shared helper `_shared/scope-expander.ts`:
   - Input: `target_id`.
   - Output: `Asset[] = { host, base_url, source: 'apex'|'subdomain'|'related' }` pulled from `discovered_endpoints` + `recon-engine` results.
   - Dedup, filter dead (`dead_targets`), respect scope rules.
2. **Orchestrator change**: `mythos-orchestrator` enqueues one `scan_step` per asset, not per target. New `scan_jobs.payload = { asset, phase }`.
3. Worker concurrency cap per target: 8 parallel assets, 4 parallel endpoints per asset.

### Phase 2 — Per-parameter, per-method battery (kills gap #2, #4, #7)

1. New helper `_shared/injection-matrix.ts` that, for each endpoint, yields the **full injection plan**:
   ```text
   for method in [GET, POST, PUT, PATCH, DELETE, OPTIONS]:
     for location in [query, body_json, body_form, body_multipart, path, header, cookie]:
       for param in extracted_params(endpoint, location):
         for payload_class in [XSS, SQLi, SSRF, LFI, RCE, SSTI, NoSQLi, XXE, OpenRedirect]:
           for payload in SecLists_top_N(payload_class) ∪ WAF_bypass_variants:
             yield Probe(method, location, param, payload)
   ```
2. `advanced-fuzzer` rewritten to consume this matrix instead of its current hand-rolled loop.
3. Hard caps to prevent explosion: 30 payloads/class, smart sampling (skip class if first 5 baseline-equal), reuse `safeFetch` with 6 s timeout.
4. Every confirmed hit → `recordFinding({autoEnqueueExploit:true})` with the exact `(method, location, param, payload)`.

### Phase 3 — Forms & file uploads actually run (kills gap #3)

1. `dom-fuzz` writes harvested forms into a new `discovered_forms` table (action, method, fields, enctype).
2. New worker case `form_attack`: for each form, POST with payloads in every field; for multipart forms, run `upload-fuzzer` with polyglot library:
   - `xss.svg`, `shell.php.jpg`, `zipslip.zip`, `xxe.docx`, `huge.pdf` (DoS canary), `cve-2021-22204.jpg` (ExifTool).
3. Upload responses inspected for filename echo, path leak, executed-content markers, OOB callback from server-side render.

### Phase 4 — Recursive chain-finder (kills gap #5)

1. `chain-finder` becomes idempotent and re-entrant: after a queued chain step itself reaches `proof_tier='exploited'`, a DB trigger re-invokes `chain-finder` on the new finding. Depth cap = 6, breadth cap = 3 per node.
2. New table `kill_chain_graph_edges` records every (parent_finding, child_finding, primitive) edge so the UI can draw the real attack tree.
3. Primitives library (`_shared/primitives.ts`): cookie, JWT, leaked-id, SQLi-read, SSRF-pivot, file-read — chain-finder must declare which primitive it is consuming and which it produces.

### Phase 5 — Verification (mandatory)

Extend `e2e-selftest` with new assertions against `testaspnet.vulnweb.com` + `testphp.vulnweb.com`:

- `assets_scanned ≥ 3` (apex + ≥2 subdomains)
- `methods_tested distinct ≥ 4`
- `params_fuzzed ≥ 25`
- `form_submissions ≥ 5`
- `upload_attempts ≥ 3`
- `kill_chain_depth ≥ 3`

No "done" without these passing — output pasted verbatim.

---

## Technical details

- **New tables (migration)**: `discovered_forms`, `kill_chain_graph_edges`, `scan_assets` (materialized scope). All with RLS admin-read + service_role full, GRANTs included.
- **New shared modules**: `_shared/scope-expander.ts`, `_shared/injection-matrix.ts`, `_shared/primitives.ts`, `_shared/polyglot-files.ts`.
- **Rewrites**: `advanced-fuzzer/index.ts` (matrix-driven), `mythos-orchestrator/index.ts` (per-asset fan-out), `chain-finder/index.ts` (recursive), `scan-job-worker/index.ts` (new job types `form_attack`, `upload_attack`, `method_matrix`).
- **DB trigger**: `after_finding_exploited` → `pg_notify` → invokes `chain-finder` edge function via `net.http_post` (or a 30 s cron sweeper to avoid extension dependency).
- **Budget guards**: per-run hard cap (e.g. 5000 probes/asset) so a wide subdomain set cannot drown the worker again.
- **Backwards compat**: existing `scan_jobs` rows keep working; new types are additive.

## Order of execution (single pass)

1. Migration: new tables + GRANTs + RLS + trigger.
2. Shared helpers (scope-expander, injection-matrix, polyglot-files, primitives).
3. Rewrite advanced-fuzzer + orchestrator + worker.
4. Wire dom-fuzz → discovered_forms; enqueue form_attack/upload_attack.
5. Recursive chain-finder + edges table writes.
6. Extend e2e-selftest, run it, paste results.

Approve and I execute Phases 1–5 in one implementation, ending with the new e2e-selftest output verbatim.
