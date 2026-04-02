/**
 * PayloadRanker.ts — Reputation Scoring
 * Tracks the success rate of every SecLists file in the Experience Vault.
 * Promotes effective payloads and demotes those that consistently fail.
 */

import { supabase } from "@/integrations/supabase/client";

export interface PayloadReputation {
  payload: string;
  successCount: number;
  failureCount: number;
  totalUses: number;
  successRate: number;
  avgConfidence: number;
  lastUsed: string;
  bestVulnClass: string;
}

export interface FileReputation {
  filePath: string;
  payloadsUsed: number;
  confirmedHits: number;
  hitRate: number;
  avgReward: number;
}

/**
 * Get reputation scores for all payloads in the Experience Vault.
 * Returns a Map of payload → score (0-100).
 */
export async function getPayloadReputations(): Promise<Map<string, number>> {
  const reputations = new Map<string, number>();

  const { data } = await supabase
    .from("experience_vault" as any)
    .select("payload_used, outcome, confidence_score, reward_score")
    .order("created_at", { ascending: false })
    .limit(1000);

  if (!data) return reputations;

  // Aggregate stats per payload
  const stats = new Map<string, { success: number; failure: number; totalConfidence: number }>();

  for (const exp of data as any[]) {
    const key = exp.payload_used;
    const existing = stats.get(key) || { success: 0, failure: 0, totalConfidence: 0 };

    if (exp.outcome === "confirmed") {
      existing.success++;
    } else {
      existing.failure++;
    }
    existing.totalConfidence += exp.confidence_score || 0;
    stats.set(key, existing);
  }

  // Calculate reputation score
  for (const [payload, stat] of stats) {
    const total = stat.success + stat.failure;
    const successRate = total > 0 ? stat.success / total : 0;
    const avgConfidence = total > 0 ? stat.totalConfidence / total : 0;

    // Weighted score: 60% success rate + 30% avg confidence + 10% usage bonus
    const usageBonus = Math.min(total * 2, 10);
    const score = Math.round(successRate * 60 + (avgConfidence / 100) * 30 + usageBonus);

    reputations.set(payload, Math.min(100, score));
  }

  return reputations;
}

/**
 * Get top-performing payloads for a specific vuln class.
 */
export async function getTopPayloads(
  vulnClass: string,
  limit = 20
): Promise<PayloadReputation[]> {
  const { data } = await supabase
    .from("experience_vault" as any)
    .select("*")
    .eq("vuln_class", vulnClass)
    .order("reward_score", { ascending: false })
    .limit(200);

  if (!data) return [];

  // Group by payload
  const payloadStats = new Map<string, {
    success: number; failure: number; totalConfidence: number;
    totalReward: number; lastUsed: string;
  }>();

  for (const exp of data as any[]) {
    const key = exp.payload_used;
    const existing = payloadStats.get(key) || {
      success: 0, failure: 0, totalConfidence: 0,
      totalReward: 0, lastUsed: exp.created_at,
    };

    if (exp.outcome === "confirmed") existing.success++;
    else existing.failure++;
    existing.totalConfidence += exp.confidence_score || 0;
    existing.totalReward += exp.reward_score || 0;
    if (exp.created_at > existing.lastUsed) existing.lastUsed = exp.created_at;

    payloadStats.set(key, existing);
  }

  const results: PayloadReputation[] = [];
  for (const [payload, stats] of payloadStats) {
    const total = stats.success + stats.failure;
    results.push({
      payload,
      successCount: stats.success,
      failureCount: stats.failure,
      totalUses: total,
      successRate: total > 0 ? Math.round((stats.success / total) * 100) : 0,
      avgConfidence: total > 0 ? Math.round(stats.totalConfidence / total) : 0,
      lastUsed: stats.lastUsed,
      bestVulnClass: vulnClass,
    });
  }

  return results
    .sort((a, b) => b.successRate - a.successRate || b.avgConfidence - a.avgConfidence)
    .slice(0, limit);
}

/**
 * Get statistics for how well specific SecLists categories perform.
 */
export async function getSecListsFileStats(): Promise<FileReputation[]> {
  const { data } = await supabase
    .from("experience_vault" as any)
    .select("payload_used, outcome, reward_score, metadata")
    .limit(500);

  if (!data) return [];

  // For now, aggregate by vuln class as a proxy for file category
  const fileStats = new Map<string, { used: number; hits: number; totalReward: number }>();

  for (const exp of data as any[]) {
    const category = (exp.metadata as any)?.secListsFile || "general";
    const existing = fileStats.get(category) || { used: 0, hits: 0, totalReward: 0 };
    existing.used++;
    if (exp.outcome === "confirmed") existing.hits++;
    existing.totalReward += exp.reward_score || 0;
    fileStats.set(category, existing);
  }

  return [...fileStats.entries()].map(([path, stats]) => ({
    filePath: path,
    payloadsUsed: stats.used,
    confirmedHits: stats.hits,
    hitRate: stats.used > 0 ? Math.round((stats.hits / stats.used) * 100) : 0,
    avgReward: stats.used > 0 ? Math.round((stats.totalReward / stats.used) * 10) / 10 : 0,
  })).sort((a, b) => b.hitRate - a.hitRate);
}
