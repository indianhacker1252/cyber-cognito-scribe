# Elite VAPT Hardening Plan

Twelve root-cause issues, mapped to concrete work. Foundation shipped this pass;
integration passes explicitly enumerated so nothing is left half-wired.

## Foundation (this pass — SHIPPED)
- `_shared/payloads-att.ts` — on-demand PayloadsAllTheThings loader (issue 12).
- `_shared/ai-mutator.ts` — AI-as-mutator: LLM sees baseline response + PayloadsAllTheThings seeds and reasons about targeted mutations (issues 1, 3, 11).
- `_shared/ai-confidence.ts` — mandatory 0-100 AI confidence gate with hard heuristic pre-filter that blocks "response-code-only" promotions and fails closed when AI is unavailable (issues 1, 4, 6).

## Integration Pass 1 — findings gate (next)
Wire `scoreConfidence` + `mayPromote` into every finding writer so nothing
lands in `vulnerability_findings.status='accepted'` without >=85 score:
- `_shared/findings-writer.ts`
- `_shared/ai-confirm-gate.ts` (replace legacy check)
- `xss-reflection-promoter`, `param-bruteforce-xss`, `advanced-fuzzer`,
  `matrix-fuzzer`, `form-attacker`, `differential-oracle`, `ssrf-deep`,
  `advanced-detectors`, `exploit-engine`
Directly addresses issue 4 (false positives) and issue 6 (exploit engine
must confirm).

## Integration Pass 2 — mutator adoption
Replace static payload-list fuzzing loops with `mutateWithAi` calls in:
- `advanced-fuzzer` (per-param round)
- `matrix-fuzzer` (per-injection-point)
- `form-attacker`
- `request-mutator` (already AI-shaped — swap to shared helper)
- `request-repeater` (add AI-driven tamper mode)
Directly addresses issues 1, 3, 11.

## Integration Pass 3 — recon depth
Extend `recon-engine` and `recon-deep`:
- DNS: A/AAAA/CNAME/MX/NS/TXT/SPF/DMARC/DNSKEY via DoH.
- Subdomains: crt.sh + certspotter + Wayback fallback.
- Ports (top 100): via existing worker dispatch (already present).
- Tech detection: Wappalyzer-lite signatures on headers+HTML+JS bundle names.
- JS deep: parse `<script src>` + inline for endpoints, secrets, framework versions (js-deep-expand already exists — invoke it always, not conditionally).
- Sensitive path enum: seclists common.txt sample.
- Headers audit: CSP/HSTS/XFO/CORP/COOP/COEP/Referrer-Policy.
- Architecture summary: LLM digest of all recon output → stored on target for downstream modules.
Addresses issues 9, 10.

## Integration Pass 4 — NVD + OWASP driven testing
- `nvd-intel-sync` already ingests CVEs; add step that maps detected tech
  versions → applicable CVEs → auto-enqueues `cve-to-exploit` with the
  CVE PoC template (issue 2).
- Materialize OWASP Top 10 checklist per target and gate scan completion
  on coverage of all 10 categories with confidence >=50 (issue 2).

## Integration Pass 5 — Mythos + chaining
- `mythos-chainer` already exists; enforce it runs after every scan with
  >=2 accepted findings (issue 7, 8).
- `chain-finder` → run confidence gate on chained proofs.
- `exploit-chain-runner` → auto-execute proposed chains in sandbox with
  fail-closed evidence capture (issue 8).

## Integration Pass 6 — retry / cost control
- Every module already has `checkLoopGuard`; audit that ALL enqueue
  paths use `enqueueJob` with `dedupExtraKey` (issue 5).
- Add "no-progress" watchdog: if a module runs 3x with zero findings AND
  zero new endpoints, mark it saturated for 24h.

## Status
Foundation compiles standalone. Integration passes are sequential — each
depends on the previous being wired without regressions.
