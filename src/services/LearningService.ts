import { supabase } from "@/integrations/supabase/client";

export interface SuppressionVector {
  id: string;
  finding_type: string;
  vuln_class: string | null;
  request_pattern: Record<string, unknown>;
  response_pattern: Record<string, unknown>;
  suppression_reason: string | null;
  created_at: string;
}

/**
 * False Positive Feedback Loop / Learning Service
 * Stores suppression vectors from human-confirmed false positives
 * and cross-references future scans against this database.
 */
export async function markAsFalsePositive(
  findingType: string,
  vulnClass: string | null,
  requestPattern: Record<string, unknown>,
  responsePattern: Record<string, unknown>,
  reason: string,
  targetId?: string
): Promise<boolean> {
  const { error } = await supabase.from("suppression_vectors").insert([{
    target_id: targetId || null,
    finding_type: findingType,
    vuln_class: vulnClass,
    request_pattern: requestPattern as any,
    response_pattern: responsePattern as any,
    suppression_reason: reason,
  }]);

  return !error;
}

export async function checkSuppression(
  findingType: string,
  vulnClass: string | null,
  requestData: Record<string, unknown>,
  responseData: Record<string, unknown>
): Promise<{ isSuppressed: boolean; matchedVector: SuppressionVector | null }> {
  const { data: vectors } = await supabase
    .from("suppression_vectors")
    .select("*")
    .eq("finding_type", findingType);

  if (!vectors || vectors.length === 0) return { isSuppressed: false, matchedVector: null };

  for (const vec of vectors) {
    const reqPattern = vec.request_pattern as Record<string, unknown> || {};
    const resPattern = vec.response_pattern as Record<string, unknown> || {};

    // Match if vuln_class matches and patterns overlap
    if (vulnClass && vec.vuln_class && vec.vuln_class !== vulnClass) continue;

    let matches = true;

    // Check request pattern keys
    for (const [key, value] of Object.entries(reqPattern)) {
      if (requestData[key] !== value) {
        matches = false;
        break;
      }
    }

    // Check response pattern keys
    if (matches) {
      for (const [key, value] of Object.entries(resPattern)) {
        if (responseData[key] !== value) {
          matches = false;
          break;
        }
      }
    }

    if (matches && Object.keys(reqPattern).length > 0) {
      return { isSuppressed: true, matchedVector: vec as SuppressionVector };
    }
  }

  return { isSuppressed: false, matchedVector: null };
}

export async function getSuppressionVectors(): Promise<SuppressionVector[]> {
  const { data } = await supabase
    .from("suppression_vectors")
    .select("*")
    .order("created_at", { ascending: false });
  return (data || []) as SuppressionVector[];
}

export async function deleteSuppressionVector(id: string): Promise<boolean> {
  const { error } = await supabase.from("suppression_vectors").delete().eq("id", id);
  return !error;
}
