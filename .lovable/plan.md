# Triple-Verification Before Report

Goal: stop noisy findings from reaching the final report. A finding only enters the PDF as **CONFIRMED** when it survives three independent checks. Anything weaker either ships as **NEEDS-REVIEW** (flagged) or is held back.

## Verification ladder

```text
  Stage 1: Baseline capture       → record clean response (status, length, body hash)
        ↓
  Stage 2: Mutated probe           → fire payload, diff against baseline
        ↓
  Stage 3: Re-baseline + canary    → re-fetch clean URL, ensure no drift; replay payload twice
        ↓
  Confidence math (0–100)
        ↓
   ≥95 → confirmed   |   75–94 → needs_review   |   <75 → inconclusive (excluded)
```

A finding is **confirmed** only if all three are true:
1. Mutated response differs from baseline beyond per-class thresholds (e.g. SSRF needs status 500 + >200 byte delta; SQLi needs error-pattern match OR >25% length delta).
2. Re-baseline matches original baseline (target wasn't drifting on its own).
3. Payload replay is deterministic — same delta on two consecutive sends.

## What gets built

### 1. Shared verifier — `supabase/functions/_shared/triple-verify.ts`
- `captureBaseline(url, method, headers)` → `{ status, length, hash, blocked }`
- `runMutated(url, method, payload, baseline)` → `{ status, length, hash, delta, signals[] }`
- `verify(finding)` returns `{ confidence, tier, reasons[], stages: {baseline, mutated, rebaseline, replay} }`
  - confidence formula: weighted sum of stage signals + class-specific detectors (reuses `EXEC_DETECTORS`)
  - canary drift detected → confidence capped at 60
  - replay non-deterministic → capped at 70

### 2. Verification orchestrator — `supabase/functions/triple-verify/index.ts`
- Input: `{ findingId }`
- Pulls finding + endpoint, runs the 3 stages with `safeFetch` (4–8s timeouts, 50s budget)
- Writes back to `vulnerability_findings`:
  - `confidence_score`, `validation_status` (`confirmed` | `needs_review` | `inconclusive`)
  - `triage_reasoning` (human-readable stage breakdown)
  - `evidence.triple_verify` (raw stage data for the report)
- Always returns 200 OK; errors land in JSON body

### 3. Auto-routing in `mythos-debate` and `triage-brain`
After the existing debate writes a candidate finding, enqueue `triple-verify` instead of marking it directly. Status mapping:
- ≥95 → `confirmed`, auto-promote to `exploit-engine`
- 75–94 → `needs_review`, surface in Findings list with amber badge
- <75 → `inconclusive`, hidden from default views

### 4. Report gating — `src/services/PdfReport.ts`
- `generateBulkPdf` filters to `validation_status IN ('confirmed','needs_review')` by default
- Each finding page renders a status pill: green CONFIRMED or amber NEEDS REVIEW (with a one-line "why flagged" from `triage_reasoning`)
- Add a summary table: counts by status alongside counts by severity
- New parameter `{ includeNeedsReview: boolean }` (default true) so auditors can export confirmed-only

### 5. UI — `src/pages/Findings.tsx`
- New filter chip: All / Confirmed / Needs Review / Inconclusive
- Badge color for `needs_review` (amber, distinct from `verified` green)
- "Re-verify" button on each finding → calls `triple-verify` edge function
- Tooltip on confidence score showing the 3-stage breakdown

### 6. Migration
- Backfill `validation_status` defaults: existing rows with `confidence_score >= 95` → `confirmed`; 75–94 → `needs_review`; rest → `inconclusive`
- Add index on `(target_id, validation_status)` for fast filtering

## Out of scope (this round)
- Refactoring exploit-engine or proof-engine internals
- Changes to recon / variant-gen
- Per-vuln-class detector tuning (uses existing `EXEC_DETECTORS`)

## Acceptance criteria
- A synthetic test target produces: confirmed SQLi (95+), needs-review reflected XSS (~85), inconclusive timing-only SSRF (<75)
- PDF export contains only confirmed + needs-review, with status pills
- Re-running verify on an unchanged finding yields the same tier (deterministic)
