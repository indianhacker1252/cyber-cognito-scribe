/**
 * AuditTrailStore - Secure Evidence Chain
 * Captures the complete validation history and stores it
 * as a structured evidence chain in the database.
 */

import { supabase } from "@/integrations/supabase/client";
import type { AdaptiveValidationResult, AdaptationAttempt } from "./AdaptiveRunner";

export interface EvidenceChainRecord {
  id: string;
  finding_id: string | null;
  approval_id: string | null;
  target_id: string;
  initial_request: Record<string, unknown>;
  filter_classification: string;
  adaptation_steps: SerializedAttempt[];
  final_poc_script: string | null;
  final_poc_language: string;
  verification_status: string;
  ai_reasoning: string | null;
  audit_report_markdown: string | null;
  cvss_score: number | null;
  cvss_vector: string | null;
  created_at: string;
}

interface SerializedAttempt {
  iteration: number;
  adaptationName: string;
  adaptationType: string;
  description: string;
  transformedPayload: string;
  statusCode: number;
  classification: string;
  success: boolean;
  reasoning: string;
}

function serializeAttempts(attempts: AdaptationAttempt[]): SerializedAttempt[] {
  return attempts.map((a) => ({
    iteration: a.iteration,
    adaptationName: a.adaptationApplied.name,
    adaptationType: a.adaptationApplied.type,
    description: a.adaptationApplied.description,
    transformedPayload: a.transformedPayload,
    statusCode: a.filterAnalysis.statusCode,
    classification: a.filterAnalysis.classification,
    success: a.success,
    reasoning: a.reasoning,
  }));
}

export async function storeEvidenceChain(params: {
  findingId?: string;
  approvalId?: string;
  targetId: string;
  result: AdaptiveValidationResult;
  pocScript?: string;
  pocLanguage?: string;
  aiReasoning?: string;
}): Promise<string> {
  const { data, error } = await supabase
    .from("adaptation_chains" as any)
    .insert({
      finding_id: params.findingId || null,
      approval_id: params.approvalId || null,
      target_id: params.targetId,
      initial_request: { payload: params.result.originalPayload },
      filter_classification: params.result.filterClassification,
      adaptation_steps: serializeAttempts(params.result.attempts),
      final_poc_script: params.pocScript || null,
      final_poc_language: params.pocLanguage || "python",
      verification_status: params.result.finalStatus,
      ai_reasoning: params.aiReasoning || null,
    } as any)
    .select("id")
    .single();

  if (error) throw error;
  return (data as any).id;
}

export async function updateEvidenceChainReport(chainId: string, report: string): Promise<void> {
  const { error } = await supabase
    .from("adaptation_chains" as any)
    .update({ audit_report_markdown: report } as any)
    .eq("id", chainId);

  if (error) throw error;
}

export async function getEvidenceChain(chainId: string): Promise<EvidenceChainRecord | null> {
  const { data, error } = await supabase
    .from("adaptation_chains" as any)
    .select("*")
    .eq("id", chainId)
    .single();

  if (error) return null;
  return data as unknown as EvidenceChainRecord;
}
