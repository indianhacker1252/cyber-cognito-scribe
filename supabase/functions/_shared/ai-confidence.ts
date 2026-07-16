// AI Confidence Scorer — required gate before any finding is promoted.
//
// Enforces: findings CANNOT be promoted based on response code alone.
// The LLM must see baseline + mutated raw response pair, evidence class,
// and known-false-positive signatures. It returns:
//   - confidenceScore 0-100
//   - verdict: confirmed | likely | uncertain | false_positive
//   - required_next_step: what would raise confidence (e.g. "browser exec proof")
//
// Threshold rules (enforced by callers):
//   >= 90  → auto-promote to accepted
//   85-89  → confirmed, needs human/PoC before report
//   50-84  → manual_review queue (do NOT show in Findings UI)
//   < 50   → false_positive, suppress and log
//
// Every finding writer MUST call this. If AI unavailable → default is
// "uncertain" (NOT confirmed) — a hard fail-closed policy that stops the
// 200-OK false-positive flood the user identified.

import { llmCall, tryParseJson } from "./llm.ts";

export interface ConfidenceInput {
  vulnClass: string;
  payload: string;
  baseline: { status: number; length: number; snippet: string; headers?: Record<string, string> };
  mutated: { status: number; length: number; snippet: string; headers?: Record<string, string> };
  executionEvidence?: {
    browserExecuted?: boolean;
    alertFired?: boolean;
    consoleMessage?: string;
    oobCallback?: boolean;
    timeDelayMs?: number;
    dbError?: string;
    diffSignature?: string;
  };
  differentialContext?: string;
  reachability?: "public" | "authenticated" | "unknown";
}

export interface ConfidenceResult {
  confidenceScore: number;
  verdict: "confirmed" | "likely" | "uncertain" | "false_positive";
  reasoning: string;
  requiredNextStep: string;
  provider: string;
  usedFallback: boolean;
}

export async function scoreConfidence(
  input: ConfidenceInput,
  db: any,
  targetId?: string,
): Promise<ConfidenceResult> {
  const evidence = input.executionEvidence || {};
  // Hard heuristic pre-checks: eliminate obvious garbage before LLM.
  const noExecEvidence =
    !evidence.browserExecuted &&
    !evidence.alertFired &&
    !evidence.oobCallback &&
    !evidence.timeDelayMs &&
    !evidence.dbError;
  const trivialDiff =
    input.baseline.status === input.mutated.status &&
    Math.abs(input.baseline.length - input.mutated.length) < 32;
  if (noExecEvidence && trivialDiff) {
    return {
      confidenceScore: 15,
      verdict: "false_positive",
      reasoning:
        "No execution evidence and no meaningful response delta — this is the classic response-code-only false positive pattern.",
      requiredNextStep: "Obtain browser execution proof, OOB callback, timing delay, or >32-byte differential.",
      provider: "heuristic",
      usedFallback: false,
    };
  }

  const systemPrompt = `You are a senior VAPT triage analyst. Score a finding 0-100 based on EVIDENCE, not response codes.

Rules:
- Score < 50 for "reflection with no browser execution" (this is the #1 false positive source).
- Score < 50 for XSS findings without alertFired/consoleMessage/domExecuted.
- Score < 50 for SSRF findings without OOB callback or 500 status + >200 byte delta.
- Score < 50 for SQLi without dbError, boolean/timing differential, or UNION extraction.
- Score >= 90 only when execution evidence is concrete and reproducible.
- Return STRICT JSON.`;

  const userPrompt = JSON.stringify({
    finding: {
      vulnClass: input.vulnClass,
      payload: input.payload.slice(0, 500),
      reachability: input.reachability || "unknown",
    },
    baseline: {
      status: input.baseline.status,
      length: input.baseline.length,
      snippet: input.baseline.snippet.slice(0, 600),
    },
    mutated: {
      status: input.mutated.status,
      length: input.mutated.length,
      snippet: input.mutated.snippet.slice(0, 600),
    },
    executionEvidence: evidence,
    differentialContext: input.differentialContext || "",
    outputSchema: {
      confidenceScore: "0-100",
      verdict: "confirmed|likely|uncertain|false_positive",
      reasoning: "one paragraph",
      requiredNextStep: "concrete action that would raise confidence",
    },
  });

  const res = await llmCall({
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: userPrompt },
    ],
    json: true,
    temperature: 0.1,
    maxTokens: 600,
    db,
    targetId,
    phase: `ai-confidence:${input.vulnClass}`,
  });

  if (!res.ok) {
    // Fail closed — no LLM means uncertain, NOT confirmed.
    return {
      confidenceScore: 40,
      verdict: "uncertain",
      reasoning: `AI confidence scorer unavailable (${res.error || "no provider"}). Fail-closed to prevent false positives.`,
      requiredNextStep: "Enable an AI provider (Lovable/OpenAI/Gemini/Anthropic) to enable auto-confidence.",
      provider: res.provider,
      usedFallback: true,
    };
  }
  const parsed = tryParseJson<{
    confidenceScore: number;
    verdict: ConfidenceResult["verdict"];
    reasoning: string;
    requiredNextStep: string;
  }>(res.text);
  if (!parsed || typeof parsed.confidenceScore !== "number") {
    return {
      confidenceScore: 40,
      verdict: "uncertain",
      reasoning: "AI returned unparseable output; fail-closed.",
      requiredNextStep: "Investigate LLM output shape.",
      provider: res.provider,
      usedFallback: true,
    };
  }
  const score = Math.max(0, Math.min(100, Math.round(parsed.confidenceScore)));
  let verdict = parsed.verdict;
  if (score >= 90) verdict = "confirmed";
  else if (score >= 85) verdict = "likely";
  else if (score >= 50) verdict = "uncertain";
  else verdict = "false_positive";
  return {
    confidenceScore: score,
    verdict,
    reasoning: (parsed.reasoning || "").slice(0, 2000),
    requiredNextStep: (parsed.requiredNextStep || "").slice(0, 500),
    provider: res.provider,
    usedFallback: false,
  };
}

/** True if a finding may be promoted to the Findings UI (score >= 85). */
export function mayPromote(r: ConfidenceResult): boolean {
  return r.confidenceScore >= 85 && (r.verdict === "confirmed" || r.verdict === "likely");
}
