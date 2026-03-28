import { supabase } from "@/integrations/supabase/client";

export interface TriageResult {
  confidenceScore: number;
  classification: "deep_finding" | "confirmed" | "manual_review" | "likely_false_positive";
  reasoning: string;
  recommendedAction: string;
}

/**
 * AI-Driven Triage Classifier
 * Uses high-reasoning LLM to classify findings with a 0-100 confidence score.
 * Below 85% → Manual Review queue. 90%+ → Deep Finding.
 */
export async function triageFinding(finding: {
  title: string;
  vulnClass: string;
  severity: string;
  payload: string;
  requestData?: Record<string, unknown>;
  responseData?: Record<string, unknown>;
  baselineResponse?: Record<string, unknown>;
  mutatedResponse?: Record<string, unknown>;
  techStack?: Record<string, string | undefined>;
  executionEvidence?: string;
  reachabilityStatus?: string;
}): Promise<TriageResult> {
  try {
    const { data, error } = await supabase.functions.invoke("triage-brain", {
      body: { finding },
    });

    if (error) throw error;

    const score = data?.confidenceScore ?? 0;
    const reasoning = data?.reasoning ?? "AI triage unavailable";

    let classification: TriageResult["classification"];
    if (score >= 90) classification = "deep_finding";
    else if (score >= 85) classification = "confirmed";
    else if (score >= 50) classification = "manual_review";
    else classification = "likely_false_positive";

    let recommendedAction: string;
    if (classification === "deep_finding") recommendedAction = "High-confidence finding — prioritize for remediation report";
    else if (classification === "confirmed") recommendedAction = "Confirmed — validate with PoC before reporting";
    else if (classification === "manual_review") recommendedAction = "Requires manual expert review — confidence below threshold";
    else recommendedAction = "Likely false positive — review suppression vectors";

    return { confidenceScore: score, classification, reasoning, recommendedAction };
  } catch {
    return {
      confidenceScore: 0,
      classification: "manual_review",
      reasoning: "Triage engine unavailable — defaulting to manual review",
      recommendedAction: "Manual review required — AI triage failed",
    };
  }
}
