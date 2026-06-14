/**
 * Coordinator.ts — Multi-Agent Mission Controller
 * Breaks scans into 100+ short-lived "Missions," spawning isolated
 * Solver Agents per endpoint/vuln-class pair.
 */

import { supabase } from "@/integrations/supabase/client";

export interface Mission {
  id: string;
  endpointId: string;
  endpointUrl: string;
  vulnClass: string;
  parameter: string;
  goal: string;
  status: "queued" | "running" | "completed" | "failed";
  solverResult: SolverResult | null;
  reviewerVerdict: ReviewerVerdict | null;
}

export interface SolverResult {
  found: boolean;
  confidence: number;
  payload: string;
  evidence: string;
  executionProof: string | null;
}

export interface ReviewerVerdict {
  agrees: boolean;
  skepticReason: string;
  finalConfidence: number;
}

/**
 * Decompose a target's endpoints into granular missions.
 */
export function decomposeMissions(
  endpoints: Array<{ id: string; url: string; parameters: Record<string, string> }>,
  vulnClasses: string[]
): Mission[] {
  const missions: Mission[] = [];
  let counter = 0;

  for (const ep of endpoints) {
    const params = ep.parameters || {};
    for (const [paramName] of Object.entries(params)) {
      for (const vc of vulnClasses) {
        counter++;
        missions.push({
          id: `mission-${counter}`,
          endpointId: ep.id,
          endpointUrl: ep.url,
          vulnClass: vc,
          parameter: paramName,
          goal: `Verify ${vc.toUpperCase()} on ${paramName}@${new URL(ep.url).pathname}`,
          status: "queued",
          solverResult: null,
          reviewerVerdict: null,
        });
      }
    }
  }

  return missions;
}

/**
 * Launch the multi-agent orchestration for a target.
 */
export async function launchCoordinatedScan(
  targetId: string
): Promise<{ totalMissions: number; taskId: string }> {
  const { data, error } = await supabase.functions.invoke("mythos-orchestrator", {
    body: {
      targetId,
      triggerType: "coordinated",
      maxIterations: 4,
    },
  });

  if (error) throw error;

  return {
    totalMissions: data?.queued ? 1 : 0,
    taskId: data?.runId || "",
  };
}

/**
 * Get mission status for a running scan.
 */
export async function getMissionStatus(
  targetId: string
): Promise<{ total: number; completed: number; findings: number }> {
  const { data: tasks } = await supabase
    .from("agent_tasks")
    .select("status, result")
    .eq("target_id", targetId)
    .eq("task_type", "mission");

  const all = tasks || [];
  return {
    total: all.length,
    completed: all.filter((t) => t.status === "completed" || t.status === "failed").length,
    findings: all.filter((t) => (t.result as any)?.findingConfirmed).length,
  };
}
