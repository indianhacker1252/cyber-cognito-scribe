// AI Confidence Scorer — required gate before any finding is promoted.
//
// v2 upgrades:
//  - Weighted evidence pre-score: each signal type contributes a fixed weight
//    (browser exec 45, OOB 45, DB error 35, timing 30, diff 20, reflection 10).
//    The LLM can only ADJUST within a band, it cannot invent proof.
//  - New verdict "not_enough_evidence" when signals sum < 25 AND diff is
//    trivial. Distinct from "false_positive" — surfaced separately in UI.
//  - Calibration log: every scored finding is upserted into
//    `ai_confidence_calibration` (score, verdict, has_hard_marker) so we can
//    compute precision/recall against user-marked outcomes over time.
//
// Threshold rules (enforced by callers via mayPromote):
//   >= 90  → auto-promote
//   85-89  → likely, needs PoC before report
//   50-84  → uncertain — manual review
//   25-49  → not_enough_evidence — do not promote, request more probes
//   < 25   → false_positive
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
    reflection?: boolean;
  };
  differentialContext?: string;
  reachability?: "public" | "authenticated" | "unknown";
}

export type Verdict = "confirmed" | "likely" | "uncertain" | "not_enough_evidence" | "false_positive";

export interface ConfidenceResult {
  confidenceScore: number;
  verdict: Verdict;
  reasoning: string;
  requiredNextStep: string;
  provider: string;
  usedFallback: boolean;
  evidenceWeights: Record<string, number>;
  evidenceTotal: number;
}

/** Weighted signals — the sum is the LLM's starting anchor. */
function weighEvidence(input: ConfidenceInput): { weights: Record<string, number>; total: number } {
  const ev = input.executionEvidence || {};
  const w: Record<string, number> = {};
  if (ev.browserExecuted || ev.alertFired) w.browser_exec = 45;
  if (ev.oobCallback) w.oob = 45;
  if (ev.dbError) w.db_error = 35;
  if (ev.timeDelayMs && ev.timeDelayMs >= 3000) w.timing = 30;
  if (ev.consoleMessage) w.console = 15;
  const lenDelta = Math.abs(input.baseline.length - input.mutated.length);
  const relDelta = lenDelta / Math.max(1, Math.max(input.baseline.length, input.mutated.length));
  if (relDelta >= 0.25 || lenDelta >= 512) w.diff_large = 20;
  else if (lenDelta >= 64) w.diff_small = 8;
  if (input.baseline.status !== input.mutated.status) w.status_change = 12;
  if (ev.reflection) w.reflection = 10;
  const total = Object.values(w).reduce((a, b) => a + b, 0);
  return { weights: w, total };
}

async function logCalibration(
  db: any,
  targetId: string | undefined,
  vulnClass: string,
  result: ConfidenceResult,
) {
  if (!db) return;
  try {
    await db.from("ai_confidence_calibration").insert({
      target_id: targetId ?? null,
      vuln_class: vulnClass,
      score: result.confidenceScore,
      verdict: result.verdict,
      provider: result.provider,
      evidence_weights: result.evidenceWeights,
      evidence_total: result.evidenceTotal,
    });
  } catch {/* table may not exist yet; ignore */}
}

export async function scoreConfidence(
  input: ConfidenceInput,
  db: any,
  targetId?: string,
): Promise<ConfidenceResult> {
  const { weights, total } = weighEvidence(input);

  // Hard heuristic pre-check: obvious garbage never reaches the LLM.
  if (total < 15) {
    const res: ConfidenceResult = {
      confidenceScore: total < 5 ? 10 : 20,
      verdict: total < 5 ? "false_positive" : "not_enough_evidence",
      reasoning: `Weighted evidence total=${total}. No meaningful execution or differential signals — classic response-code-only pattern.`,
      requiredNextStep:
        "Obtain browser execution proof, OOB callback, DB error, timing delay ≥3s, or ≥25% response delta.",
      provider: "heuristic",
      usedFallback: false,
      evidenceWeights: weights,
      evidenceTotal: total,
    };
    await logCalibration(db, targetId, input.vulnClass, res);
    return res;
  }

  const systemPrompt = `You are a senior VAPT triage analyst. A pre-scoring engine has already computed weighted evidence.
Your job: ADJUST the score within ±15 based on payload↔response semantics.

Weight rules that produced the anchor:
- browser_exec/alert: 45, oob: 45, db_error: 35, timing≥3s: 30, diff_large: 20, status_change: 12, reflection: 10.

Verdict bands (assign strictly by final score):
- >=90 confirmed  |  85-89 likely  |  50-84 uncertain  |  25-49 not_enough_evidence  |  <25 false_positive

Never invent evidence not listed. If evidence contradicts payload semantics (e.g. XSS with reflection but no exec), CAP score at 55.
Return STRICT JSON with keys: adjustment (-15..15 int), verdict, reasoning, requiredNextStep.`;

  const userPrompt = JSON.stringify({
    anchorScore: total,
    weights,
    finding: {
      vulnClass: input.vulnClass,
      payload: input.payload.slice(0, 400),
      reachability: input.reachability || "unknown",
    },
    baseline: {
      status: input.baseline.status,
      length: input.baseline.length,
      snippet: input.baseline.snippet.slice(0, 500),
    },
    mutated: {
      status: input.mutated.status,
      length: input.mutated.length,
      snippet: input.mutated.snippet.slice(0, 500),
    },
    executionEvidence: input.executionEvidence || {},
    differentialContext: input.differentialContext || "",
  });

  const res = await llmCall({
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: userPrompt },
    ],
    json: true,
    temperature: 0.1,
    maxTokens: 500,
    db,
    targetId,
    phase: `ai-confidence:${input.vulnClass}`,
  });

  const bandVerdict = (score: number): Verdict =>
    score >= 90 ? "confirmed"
    : score >= 85 ? "likely"
    : score >= 50 ? "uncertain"
    : score >= 25 ? "not_enough_evidence"
    : "false_positive";

  if (!res.ok) {
    const fallbackScore = Math.min(80, Math.max(30, total));
    const result: ConfidenceResult = {
      confidenceScore: fallbackScore,
      verdict: bandVerdict(fallbackScore) === "confirmed" ? "likely" : bandVerdict(fallbackScore),
      reasoning: `AI unavailable (${res.error || "no provider"}). Using weighted-evidence anchor only. FAIL-CLOSED for promotion.`,
      requiredNextStep: "Enable an AI provider so calibration can adjust the score.",
      provider: res.provider,
      usedFallback: true,
      evidenceWeights: weights,
      evidenceTotal: total,
    };
    // Never auto-promote without AI adjustment
    if (result.confidenceScore >= 85) result.confidenceScore = 84;
    result.verdict = bandVerdict(result.confidenceScore);
    await logCalibration(db, targetId, input.vulnClass, result);
    return result;
  }

  const parsed = tryParseJson<{
    adjustment?: number;
    verdict?: Verdict;
    reasoning?: string;
    requiredNextStep?: string;
  }>(res.text);
  const adj = Math.max(-15, Math.min(15, Math.round(Number(parsed?.adjustment ?? 0))));
  const score = Math.max(0, Math.min(100, total + adj));
  const verdict = bandVerdict(score);
  const result: ConfidenceResult = {
    confidenceScore: score,
    verdict,
    reasoning: (parsed?.reasoning || "AI adjustment applied to weighted anchor.").slice(0, 2000),
    requiredNextStep: (parsed?.requiredNextStep || "").slice(0, 500),
    provider: res.provider,
    usedFallback: false,
    evidenceWeights: weights,
    evidenceTotal: total,
  };
  await logCalibration(db, targetId, input.vulnClass, result);
  return result;
}

/** True if a finding may be promoted to the Findings UI (score >= 85). */
export function mayPromote(r: ConfidenceResult): boolean {
  return r.confidenceScore >= 85 && (r.verdict === "confirmed" || r.verdict === "likely");
}

/** True if the finding lacks enough evidence to even review — request more probes. */
export function needsMoreEvidence(r: ConfidenceResult): boolean {
  return r.verdict === "not_enough_evidence";
}
