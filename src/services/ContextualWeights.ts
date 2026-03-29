/**
 * ContextualWeights.ts — Tech-Stack Weighting Engine
 * Tracks effectiveness of vuln classes per tech stack and automatically
 * disables low-yield tests to reduce noise and speed up scans.
 */

import { supabase } from "@/integrations/supabase/client";

export interface StrategyWeight {
  id: string;
  tech_stack_key: string;
  vuln_class: string;
  tool_name: string;
  success_count: number;
  failure_count: number;
  effectiveness_pct: number;
  last_updated: string;
}

/**
 * Derive a normalized tech stack key for lookups.
 */
export function deriveTechStackKey(techStack: Record<string, string | undefined>): string {
  const parts: string[] = [];
  if (techStack.server) parts.push(techStack.server.split("/")[0].toLowerCase());
  if (techStack.framework) parts.push(techStack.framework.split("/")[0].toLowerCase());
  if (techStack.poweredBy) parts.push(techStack.poweredBy.split("/")[0].toLowerCase());
  return parts.join(":") || "unknown";
}

/**
 * Record a success or failure for a vuln class + tech stack combo.
 */
export async function recordOutcome(
  techStack: Record<string, string | undefined>,
  vulnClass: string,
  toolName: string,
  success: boolean
): Promise<void> {
  const key = deriveTechStackKey(techStack);

  // Try upsert
  const { data: existing } = await supabase
    .from("strategy_weights" as any)
    .select("*")
    .eq("tech_stack_key", key)
    .eq("vuln_class", vulnClass)
    .eq("tool_name", toolName)
    .single();

  if (existing) {
    const record = existing as unknown as StrategyWeight;
    const newSuccess = record.success_count + (success ? 1 : 0);
    const newFailure = record.failure_count + (success ? 0 : 1);
    const total = newSuccess + newFailure;
    const effectiveness = total > 0 ? (newSuccess / total) * 100 : 50;

    await supabase
      .from("strategy_weights" as any)
      .update({
        success_count: newSuccess,
        failure_count: newFailure,
        effectiveness_pct: Math.round(effectiveness * 10) / 10,
        last_updated: new Date().toISOString(),
      } as any)
      .eq("id", record.id);
  } else {
    await supabase
      .from("strategy_weights" as any)
      .insert({
        tech_stack_key: key,
        vuln_class: vulnClass,
        tool_name: toolName,
        success_count: success ? 1 : 0,
        failure_count: success ? 0 : 1,
        effectiveness_pct: success ? 100 : 0,
      } as any);
  }
}

/**
 * Get effectiveness weights for a given tech stack.
 * Returns vuln classes sorted by effectiveness.
 */
export async function getWeights(
  techStack: Record<string, string | undefined>
): Promise<StrategyWeight[]> {
  const key = deriveTechStackKey(techStack);

  const { data } = await supabase
    .from("strategy_weights" as any)
    .select("*")
    .eq("tech_stack_key", key)
    .order("effectiveness_pct", { ascending: false });

  return (data || []) as unknown as StrategyWeight[];
}

/**
 * Determine which vuln classes should be SKIPPED for a tech stack.
 * Any class with < 10% effectiveness after 5+ tests is disabled.
 */
export async function getDisabledClasses(
  techStack: Record<string, string | undefined>
): Promise<string[]> {
  const weights = await getWeights(techStack);
  const minTests = 5;

  return weights
    .filter((w) => {
      const total = w.success_count + w.failure_count;
      return total >= minTests && w.effectiveness_pct < 10;
    })
    .map((w) => w.vuln_class);
}

/**
 * Get a prioritized list of vuln classes for a tech stack.
 * High-effectiveness classes come first.
 */
export async function getPrioritizedClasses(
  techStack: Record<string, string | undefined>,
  allClasses: string[]
): Promise<string[]> {
  const weights = await getWeights(techStack);
  const disabled = await getDisabledClasses(techStack);

  const weightMap = new Map(weights.map((w) => [w.vuln_class, w.effectiveness_pct]));

  return allClasses
    .filter((c) => !disabled.includes(c))
    .sort((a, b) => (weightMap.get(b) || 50) - (weightMap.get(a) || 50));
}

/**
 * Get all weights for the dashboard.
 */
export async function getAllWeights(): Promise<StrategyWeight[]> {
  const { data } = await supabase
    .from("strategy_weights" as any)
    .select("*")
    .order("effectiveness_pct", { ascending: false });

  return (data || []) as unknown as StrategyWeight[];
}
