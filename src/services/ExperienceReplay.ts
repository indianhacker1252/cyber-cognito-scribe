/**
 * ExperienceReplay.ts — Success/Failure Memory Vault
 * Stores "Security Experiences" from every scan and queries
 * past results to guide future testing strategies.
 */

import { supabase } from "@/integrations/supabase/client";

export interface SecurityExperience {
  id: string;
  target_id: string | null;
  tech_stack: Record<string, string | undefined>;
  vuln_class: string;
  payload_used: string;
  http_method: string;
  response_status: number | null;
  response_length: number | null;
  response_snippet: string | null;
  outcome: "confirmed" | "false_positive" | "blocked" | "error";
  confidence_score: number;
  reward_score: number;
  metadata: Record<string, unknown>;
  created_at: string;
}

/**
 * Record a scan experience into the Memory Vault.
 */
export async function recordExperience(params: {
  targetId?: string;
  techStack: Record<string, string | undefined>;
  vulnClass: string;
  payloadUsed: string;
  httpMethod?: string;
  responseStatus?: number;
  responseLength?: number;
  responseSnippet?: string;
  outcome: "confirmed" | "false_positive" | "blocked" | "error";
  confidenceScore?: number;
  rewardScore?: number;
  metadata?: Record<string, unknown>;
}): Promise<string | null> {
  const { data, error } = await supabase
    .from("experience_vault" as any)
    .insert({
      target_id: params.targetId || null,
      tech_stack: params.techStack,
      vuln_class: params.vulnClass,
      payload_used: params.payloadUsed,
      http_method: params.httpMethod || "GET",
      response_status: params.responseStatus || null,
      response_length: params.responseLength || null,
      response_snippet: params.responseSnippet || null,
      outcome: params.outcome,
      confidence_score: params.confidenceScore || 0,
      reward_score: params.rewardScore || 0,
      metadata: params.metadata || {},
    } as any)
    .select("id")
    .single();

  if (error) {
    console.error("Failed to record experience:", error);
    return null;
  }
  return (data as any)?.id || null;
}

/**
 * Query past experiences for a similar tech stack and vuln class.
 * Returns what worked (confirmed) and what didn't (false_positive/blocked).
 */
export async function queryPastExperiences(
  techStack: Record<string, string | undefined>,
  vulnClass: string,
  limit = 20
): Promise<{ successes: SecurityExperience[]; failures: SecurityExperience[] }> {
  const { data } = await supabase
    .from("experience_vault" as any)
    .select("*")
    .eq("vuln_class", vulnClass)
    .order("reward_score", { ascending: false })
    .limit(limit);

  const experiences = (data || []) as unknown as SecurityExperience[];

  // Filter by tech stack similarity
  const serverKey = techStack.server?.toLowerCase() || "";
  const frameworkKey = techStack.framework?.toLowerCase() || "";

  const relevant = experiences.filter((exp) => {
    const expStack = exp.tech_stack || {};
    const expServer = ((expStack as any).server || "").toLowerCase();
    const expFramework = ((expStack as any).framework || "").toLowerCase();
    // Match if server or framework overlaps
    return (
      (serverKey && expServer.includes(serverKey.split("/")[0])) ||
      (frameworkKey && expFramework.includes(frameworkKey.split("/")[0])) ||
      (!serverKey && !frameworkKey) // no filter = return all
    );
  });

  return {
    successes: relevant.filter((e) => e.outcome === "confirmed"),
    failures: relevant.filter((e) => e.outcome === "false_positive" || e.outcome === "blocked"),
  };
}

/**
 * Get the best-performing payloads for a given vuln class.
 */
export async function getBestPayloads(vulnClass: string, limit = 5): Promise<string[]> {
  const { data } = await supabase
    .from("experience_vault" as any)
    .select("payload_used")
    .eq("vuln_class", vulnClass)
    .eq("outcome", "confirmed")
    .order("reward_score", { ascending: false })
    .limit(limit);

  return (data || []).map((d: any) => d.payload_used);
}

/**
 * Get experiences summary stats.
 */
export async function getExperienceStats(): Promise<{
  total: number;
  confirmed: number;
  falsePositives: number;
  blocked: number;
}> {
  const { data } = await supabase
    .from("experience_vault" as any)
    .select("outcome");

  const all = (data || []) as any[];
  return {
    total: all.length,
    confirmed: all.filter((e) => e.outcome === "confirmed").length,
    falsePositives: all.filter((e) => e.outcome === "false_positive").length,
    blocked: all.filter((e) => e.outcome === "blocked").length,
  };
}
