/**
 * DeepSignalTriage.ts — "Cantina-Style" Secondary AI Judge
 * Uses a high-reasoning model to review the evidence chain and only
 * promotes findings that are mathematically consistent with real vulns.
 */

import { supabase } from "@/integrations/supabase/client";

export interface DeepTriageResult {
  verdict: "promote" | "demote" | "manual_review";
  confidenceScore: number;
  mathematicalConsistency: number;
  evidenceChainValid: boolean;
  reasoning: string;
  recommendations: string[];
}

/**
 * Submit a finding's evidence chain to the secondary AI judge.
 */
export async function deepTriageFinding(params: {
  findingTitle: string;
  vulnClass: string;
  severity: string;
  payload: string;
  baselineResponse: Record<string, unknown>;
  mutatedResponse: Record<string, unknown>;
  intruderResults?: Array<{ payload: string; status: number; length: number }>;
  adaptationHistory?: Array<{ name: string; result: string }>;
  techStack: Record<string, string | undefined>;
  confidenceScore: number;
  executionEvidence?: string;
}): Promise<DeepTriageResult> {
  try {
    const { data, error } = await supabase.functions.invoke("deep-signal-triage", {
      body: { finding: params },
    });

    if (error) throw error;

    return {
      verdict: data?.verdict || "manual_review",
      confidenceScore: data?.confidenceScore ?? 0,
      mathematicalConsistency: data?.mathematicalConsistency ?? 0,
      evidenceChainValid: data?.evidenceChainValid ?? false,
      reasoning: data?.reasoning || "Deep triage unavailable",
      recommendations: data?.recommendations || [],
    };
  } catch {
    return {
      verdict: "manual_review",
      confidenceScore: 0,
      mathematicalConsistency: 0,
      evidenceChainValid: false,
      reasoning: "Deep signal triage engine unavailable — defaulting to manual review",
      recommendations: ["Review evidence chain manually"],
    };
  }
}

/**
 * Batch triage multiple findings through the deep signal judge.
 */
export async function batchDeepTriage(
  findings: Array<{
    id: string;
    title: string;
    vulnClass: string;
    severity: string;
    payload: string;
    baselineResponse: Record<string, unknown>;
    mutatedResponse: Record<string, unknown>;
    confidenceScore: number;
    techStack: Record<string, string | undefined>;
  }>
): Promise<Map<string, DeepTriageResult>> {
  const results = new Map<string, DeepTriageResult>();

  for (const finding of findings) {
    const result = await deepTriageFinding({
      findingTitle: finding.title,
      vulnClass: finding.vulnClass,
      severity: finding.severity,
      payload: finding.payload,
      baselineResponse: finding.baselineResponse,
      mutatedResponse: finding.mutatedResponse,
      confidenceScore: finding.confidenceScore,
      techStack: finding.techStack,
    });
    results.set(finding.id, result);

    // Rate limit
    await new Promise((r) => setTimeout(r, 500));
  }

  return results;
}
