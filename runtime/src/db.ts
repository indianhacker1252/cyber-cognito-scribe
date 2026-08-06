import { createClient } from "@supabase/supabase-js";

const url = process.env.SUPABASE_URL!;
const key = process.env.SUPABASE_SERVICE_ROLE_KEY!;
if (!url || !key) throw new Error("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required");

export const db = createClient(url, key, {
  auth: { persistSession: false, autoRefreshToken: false },
});

export type Session = {
  id: string;
  target_id: string;
  status: string;
  goal: string | null;
  model: string;
  provider: string;
  budget_credits: number;
  budget_seconds: number;
  credits_used: number;
  steps_taken: number;
  started_at: string | null;
  metadata: Record<string, unknown>;
};

export async function claimSession(host: string): Promise<Session | null> {
  const { data, error } = await db.rpc("claim_agent_session", { _host: host });
  if (error) {
    console.error("[db] claim_agent_session error:", error.message);
    return null;
  }
  const s = data as Session | null;
  if (!s || !s.id) return null;
  return s;
}

export async function emit(
  sessionId: string,
  targetId: string,
  kind: string,
  payload: Record<string, unknown>,
  step?: number,
) {
  await db.from("agent_events").insert({
    session_id: sessionId,
    target_id: targetId,
    kind,
    step: step ?? null,
    payload,
  });
}

export async function logToolInvocation(row: {
  session_id: string;
  target_id: string;
  step: number;
  tool: string;
  args: unknown;
  result: unknown;
  ok: boolean;
  latency_ms: number;
  cost_credits?: number;
}) {
  await db.from("tool_invocations").insert(row);
}

export async function updateSession(id: string, patch: Record<string, unknown>) {
  await db.from("agent_sessions").update(patch).eq("id", id);
}

export async function heartbeat(id: string) {
  await db.from("agent_sessions").update({ last_heartbeat: new Date().toISOString() }).eq("id", id);
}

export async function getTarget(id: string) {
  const { data } = await db.from("target_workspaces").select("*").eq("id", id).maybeSingle();
  return data;
}

export async function mergeWorldModel(targetId: string, patch: Record<string, unknown>) {
  await db.rpc("merge_world_model", { _target_id: targetId, _patch: patch });
}

export async function getWorldModel(targetId: string) {
  const { data } = await db.from("target_world_model").select("model").eq("target_id", targetId).maybeSingle();
  return (data?.model as Record<string, unknown>) ?? {};
}

// -------- Mythos L2 (experience replay) --------
export async function recordExperience(row: {
  target_id: string; session_id?: string | null;
  vuln_class: string; technique?: string | null; endpoint_pattern?: string | null;
  tech_tags?: string[]; outcome: "confirmed" | "rejected" | "partial" | "dead_end";
  confidence?: number; proof_snippet?: string | null; notes?: string | null;
}) {
  const { error } = await db.from("agent_experiences").insert(row);
  if (error) console.error("[db] recordExperience:", error.message);
}
export async function similarExperiences(targetId: string, techTags: string[] = [], limit = 20) {
  const { data } = await db.from("agent_experiences")
    .select("vuln_class,technique,endpoint_pattern,outcome,confidence,proof_snippet,notes,created_at,target_id")
    .eq("target_id", targetId)
    .order("created_at", { ascending: false }).limit(limit);
  if (data && data.length) return data;
  if (techTags.length) {
    const { data: cross } = await db.from("agent_experiences")
      .select("vuln_class,technique,endpoint_pattern,outcome,confidence,proof_snippet,notes,created_at,target_id")
      .overlaps("tech_tags", techTags)
      .order("created_at", { ascending: false }).limit(limit);
    return cross ?? [];
  }
  return [];
}

// -------- Mythos L3 (metrics) --------
export async function metric(sessionId: string, targetId: string, name: string, value = 1, tags: Record<string, unknown> = {}) {
  const { error } = await db.from("agent_metrics").insert({
    session_id: sessionId, target_id: targetId, metric: name, value, tags,
  });
  if (error) console.error("[db] metric:", error.message);
}

