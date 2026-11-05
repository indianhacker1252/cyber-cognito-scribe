# Replace deprecated AI models safely

## Confirmed issue

Current application code still selects deprecated Gateway models across edge functions, the agent-start control, and the runtime self-test (22 references). This is not only historical evidence.

The authenticated workspace catalog confirms:
- `google/gemini-2.5-flash` and `google/gemini-2.5-flash-lite`: deprecated, with expiration dated October 20, 2026.
- `google/gemini-3.6-flash`: deprecated, with expiration dated November 19, 2026.

The catalog exposes no automatic-replacement mapping for these entries. Recent production logs show successful Gemini 3.8 Flash requests, but do not establish which original model was requested. Automatic alias replacement and any future outage remain unverified; these dates alone are not evidence of an upcoming Gateway disruption.

Because this spans scan analysis, triage, report generation, agent sessions, persisted defaults, and the separately installed Oracle runner, implement a coordinated migration rather than an isolated text replacement.

## Changes

1. Replace Gateway `google/gemini-2.5-flash` and `google/gemini-3.6-flash` selections with **`google/gemini-3.8-flash`**, preserving the Flash workload tier and existing chat-completions integration.
2. Replace Gateway `google/gemini-2.5-flash-lite` selections with **`google/gemini-3.1-flash-lite`**, preserving the lightweight tier for high-volume extraction and inexpensive gates.
3. Update the agent-start default, agent-start control, and runtime self-test. Inspect the live database default and session model values before deciding whether a forward-only migration is necessary. Do not edit historical migrations or overwrite running sessions.
4. Check deploy-time configuration for affected aliases without exposing secrets. Preserve supported models, direct-provider calls, provider selection, and local inference.
5. Preserve existing output limits, streaming behavior, prompts, timers, retries, fallback routing, and error handling. Change request parameters only where compatibility testing proves it necessary.
6. Update the recorded primary-model preference and architecture rule to reflect the approved migration without duplicating model values in architecture documentation.

## Cost and behavior

Both proposed replacements are active in the authenticated workspace catalog, accept text/image/audio/video inputs, return text, and support chat completions with zero retention on that endpoint. Stay on that endpoint; do not move Gemini calls to its provider-retained Interactions surface.

Published workspace token rates, excluding cache and other serving tiers:

| Migration | Input credits / million tokens | Output credits / million tokens |
|---|---:|---:|
| Gemini 2.5 Flash → 3.8 Flash | 1.2 → 3 | 10 → 15 |
| Gemini 3.6 Flash → 3.8 Flash | 3 → 3 | 15 → 15 |
| Gemini 2.5 Flash Lite → 3.1 Flash Lite | 0.4 → 1 | 1.6 → 6 |

These compare listed model rates, not verified billing for redirected aliases. Actual cost depends on tokens used. Gemini 3.8 Flash is already succeeding in production; equivalent latency, tool behavior, and output quality must still be checked for the affected workflows.

## Verification and delivery

- Add focused model-routing regression tests and run existing runtime transport/error tests.
- Exercise representative plain-text, JSON, and streamed tool-call requests through the existing Gateway paths, including tool-result continuation. Check inference-region eligibility and terminal access errors; stop live verification if credits or access block requests.
- Verify an authenticated affected application flow with real input and read its result back through the UI. Do not launch an external-target scan as a migration smoke test.
- Check current preview diagnostics, audit remaining live deprecated references, and commit the migration.
- Report old-to-new mappings and any blocked checks; resolve the monitoring finding as fixed only after verifying the repair.
- Do not publish. Oracle runner installation requires a separate rebuild on the user's VPS; local source changes do not update that machine automatically.

## Technical scope

Gateway call sites include the shared LLM helper, vulnerability scanner, validation, package scan, fuzzer, tutoring, report rewriting, chaining, triage, variant generation, patching, PoC generation, exploit analysis, intelligence ingestion, and debate gates. The agent-session model default must be verified in the live database rather than inferred from an old migration. No security policy, target authorization, finding-proof requirement, or direct-provider migration is included.