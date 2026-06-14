/**
 * AutoRescan.ts — Recursive Target Re-Scanner
 * When a high-signal new bug is ingested, cross-references it against
 * the target database and triggers delta scans on matching tech stacks.
 */

import { supabase } from "@/integrations/supabase/client";

export interface RescanMatch {
  targetId: string;
  targetName: string;
  domain: string;
  matchedTech: string[];
  matchScore: number;
}

export interface DeltaScanResult {
  targetId: string;
  triggered: boolean;
  reason: string;
}

/**
 * Cross-reference a new intel feed against all targets in the database.
 * Returns targets whose tech stack matches the affected technology.
 */
export async function findMatchingTargets(params: {
  affectedTechStack: string[];
  vulnClass: string;
}): Promise<RescanMatch[]> {
  const matches: RescanMatch[] = [];

  // Get all completed targets
  const { data: targets } = await supabase
    .from("target_workspaces")
    .select("id, name, domain, status")
    .eq("status", "completed");

  if (!targets || targets.length === 0) return [];

  // Get recon results for each target to check tech stack
  for (const target of targets) {
    const { data: reconTask } = await supabase
      .from("agent_tasks")
      .select("result")
      .eq("target_id", target.id)
      .eq("task_type", "reconnaissance")
      .eq("status", "completed")
      .order("created_at", { ascending: false })
      .limit(1)
      .single();

    if (!reconTask?.result) continue;

    const result = reconTask.result as any;
    const fingerprint = result.tech_fingerprint || {};
    const targetTech = [
      fingerprint.server,
      fingerprint.framework,
      fingerprint.poweredBy,
    ].filter(Boolean).map((t: string) => t.toLowerCase());

    // Check for tech stack overlap
    const matchedTech = params.affectedTechStack.filter((t) =>
      targetTech.some((tt: string) => tt.includes(t.toLowerCase()) || t.toLowerCase().includes(tt))
    );

    if (matchedTech.length > 0) {
      const matchScore = Math.min(100, Math.round((matchedTech.length / Math.max(params.affectedTechStack.length, 1)) * 100));
      matches.push({
        targetId: target.id,
        targetName: target.name,
        domain: target.domain || "",
        matchedTech,
        matchScore,
      });
    }
  }

  // Sort by match score descending
  return matches.sort((a, b) => b.matchScore - a.matchScore);
}

/**
 * Trigger a delta scan on a specific target for a specific vulnerability class.
 */
export async function triggerDeltaScan(params: {
  targetId: string;
  vulnClass: string;
  intelFeedId: string;
  templatePayloads?: string[];
}): Promise<DeltaScanResult> {
  try {
    // Check if target has endpoints
    const { data: endpoints, error: epErr } = await supabase
      .from("discovered_endpoints")
      .select("id")
      .eq("target_id", params.targetId)
      .limit(1);

    if (epErr || !endpoints || endpoints.length === 0) {
      return {
        targetId: params.targetId,
        triggered: false,
        reason: "No discovered endpoints — run recon first",
      };
    }

    // Log the delta scan initiation
    const { data: task } = await supabase
      .from("agent_tasks")
      .insert({
        target_id: params.targetId,
        task_type: "intel-delta-scan",
        status: "pending",
        thought_log: [
          {
            type: "info",
            message: `Intel-driven delta scan for ${params.vulnClass}`,
            intelFeedId: params.intelFeedId,
            timestamp: new Date().toISOString(),
          },
        ],
      })
      .select()
      .single();

    if (!task) {
      return {
        targetId: params.targetId,
        triggered: false,
        reason: "Failed to create scan task",
      };
    }

    // Log scan initiation
    await supabase.from("scan_logs").insert({
      target_id: params.targetId,
      task_id: task.id,
      log_type: "info",
      message: `🔄 Intel-driven delta scan initiated for ${params.vulnClass} (from feed ${params.intelFeedId})`,
      metadata: { intelFeedId: params.intelFeedId, vulnClass: params.vulnClass },
    });

    // Trigger the unified Mythos orchestrator with intel context
    const { error: scanErr } = await supabase.functions.invoke("mythos-orchestrator", {
      body: { targetId: params.targetId, triggerType: "intel-delta", maxIterations: 3, vulnClass: params.vulnClass, intelFeedId: params.intelFeedId },
    });

    if (scanErr) {
      return {
        targetId: params.targetId,
        triggered: false,
        reason: `Scan invocation failed: ${scanErr.message}`,
      };
    }

    return {
      targetId: params.targetId,
      triggered: true,
      reason: `Delta scan triggered for ${params.vulnClass}`,
    };
  } catch (e) {
    return {
      targetId: params.targetId,
      triggered: false,
      reason: `Error: ${e instanceof Error ? e.message : "Unknown"}`,
    };
  }
}

/**
 * Run the full auto-rescan pipeline for a new intel feed entry.
 */
export async function autoRescanPipeline(params: {
  intelFeedId: string;
  vulnClass: string;
  affectedTechStack: string[];
  signalStrength: string;
}): Promise<{
  matchedTargets: number;
  rescansTriggered: number;
  results: DeltaScanResult[];
}> {
  // Only trigger rescans for high-signal intelligence
  if (params.signalStrength === "low") {
    return { matchedTargets: 0, rescansTriggered: 0, results: [] };
  }

  const matches = await findMatchingTargets({
    affectedTechStack: params.affectedTechStack,
    vulnClass: params.vulnClass,
  });

  const results: DeltaScanResult[] = [];
  let rescansTriggered = 0;

  // Only trigger for top 3 matches to avoid scan storms
  for (const match of matches.slice(0, 3)) {
    if (match.matchScore >= 50) {
      const result = await triggerDeltaScan({
        targetId: match.targetId,
        vulnClass: params.vulnClass,
        intelFeedId: params.intelFeedId,
      });
      results.push(result);
      if (result.triggered) rescansTriggered++;

      // 2s delay between scans
      await new Promise((r) => setTimeout(r, 2000));
    }
  }

  return {
    matchedTargets: matches.length,
    rescansTriggered,
    results,
  };
}
