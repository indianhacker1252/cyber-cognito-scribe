// Agentic Planner — the "XBOW brain" that picks the next 3 concrete actions.
//
// Called by phase-arbiter once recon is complete. Reads the target's world
// model + open findings + remaining OWASP checks and asks the LLM to emit a
// structured action list. Actions are enqueued as normal scan_jobs so the
// existing worker fanout still runs. Every turn lands in `planner_traces`
// with a stable trace_id so the Brain UI can render the reasoning.

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { llmCall, tryParseJson } from "../_shared/llm.ts";
import { getWorld, renderWorld } from "../_shared/world-model.ts";
import { enqueueJobs } from "../_shared/enqueue.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

// Modules the planner is allowed to enqueue. Kept narrow — everything else is
// still triggered by the deterministic phase-arbiter as a safety rail.
const ALLOWED_MODULES = new Set([
  "advanced_fuzz", "matrix_fuzz", "form_attack", "ai_intrude", "auth_replay",
  "ssrf_deep", "jwt_attack", "graphql", "race", "prototype_pollution",
  "cache_attack", "smuggling", "bac", "differential", "cve_exploit",
]);

interface PlannerAction {
  module: string;
  target_url?: string;
  param?: string;
  vuln_class?: string;
  expected_signal: string;
  priority?: number;
  rationale: string;
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

  try {
    const { targetId, maxActions = 5, reason = "manual" } = await req.json();
    if (!targetId) throw new Error("targetId required");

    const db = createClient(SUPABASE_URL, SERVICE_KEY);
    const traceId = crypto.randomUUID();

    // Bail early if credits are gone.
    const { areCreditsRecentlyExhausted } = await import("../_shared/ai-credits.ts");
    if (await areCreditsRecentlyExhausted(db, targetId, 15)) {
      return new Response(JSON.stringify({ ok: false, paused: true, reason: "no_ai_provider" }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const world = await getWorld(db, targetId);

    // Pull the top open findings so the planner reasons over real evidence.
    const { data: findings } = await db.from("vulnerability_findings")
      .select("id, title, vuln_class, severity, affected_url, evidence")
      .eq("target_id", targetId)
      .in("severity", ["critical", "high", "medium", "info"])
      .order("created_at", { ascending: false })
      .limit(15);

    // Remaining OWASP checks (never-attempted or failed).
    const { data: owasp } = await db.from("owasp_checklist")
      .select("category, check_name, check_module, status")
      .eq("target_id", targetId)
      .not("status", "in", "(evidence,passed,complete,attempted)")
      .limit(30);

    // Sample of testable endpoints.
    const { data: eps } = await db.from("discovered_endpoints")
      .select("url, method")
      .eq("target_id", targetId)
      .limit(40);

    const sys = `You are an elite offensive-security planner. Your job is to pick the next ${maxActions} concrete probing actions for this target, based on the world model and existing evidence.

Rules:
- Emit ONLY actions using modules from this allowlist: ${Array.from(ALLOWED_MODULES).join(", ")}.
- Skip vuln classes that are inapplicable to this stack (e.g. no SSTI on pure SPA).
- Prefer actions that unlock chains from existing HIGH findings.
- Each action MUST include an expected_signal the runner can verify.
- Return STRICT JSON: { "reasoning": "3-5 sentences", "actions": [ ... ] }.
- Action fields: module, target_url, param, vuln_class, expected_signal, priority (1-10), rationale.`;

    const user = JSON.stringify({
      trace_id: traceId,
      target_id: targetId,
      world_summary: renderWorld(world),
      world: world,
      open_findings: (findings || []).map((f: any) => ({
        id: f.id, title: f.title, class: f.vuln_class, severity: f.severity, url: f.affected_url,
      })),
      remaining_owasp: (owasp || []).slice(0, 20),
      sample_endpoints: (eps || []).slice(0, 15),
      max_actions: maxActions,
    });

    const res = await llmCall({
      messages: [{ role: "system", content: sys }, { role: "user", content: user }],
      json: true, temperature: 0.3, maxTokens: 1800,
      db, targetId, phase: `agent-planner:${reason}`,
    });

    let reasoning = "";
    let actions: PlannerAction[] = [];
    if (res.ok) {
      const parsed = tryParseJson<{ reasoning?: string; actions?: PlannerAction[] }>(res.text);
      reasoning = (parsed?.reasoning || "").slice(0, 2000);
      actions = (parsed?.actions || []).filter((a) => a && ALLOWED_MODULES.has(a.module)).slice(0, maxActions);
    }

    // Persist trace regardless — so the UI shows failed planner turns too.
    await db.from("planner_traces").insert({
      target_id: targetId,
      trace_id: traceId,
      turn: 0,
      world_snapshot: world,
      open_findings: (findings || []).length,
      reasoning: reasoning || res.error || "no reasoning",
      actions: actions,
      provider: res.provider,
    });

    // Enqueue as normal scan_jobs.
    let queued = 0;
    if (actions.length > 0) {
      queued = await enqueueJobs(db, actions.map((a) => ({
        target_id: targetId,
        job_type: a.module,
        priority: Math.max(1, Math.min(10, a.priority || 6)),
        payload: {
          url: a.target_url,
          param: a.param,
          vuln_class: a.vuln_class,
          expected_signal: a.expected_signal,
          rationale: a.rationale,
          source: "agent-planner",
          trace_id: traceId,
        },
        next_run_at: new Date().toISOString(),
        dedupWindowMs: 30 * 60_000,
        dedupExtraKey: `${a.target_url || ""}:${a.param || ""}`,
      })));
    }

    await db.from("scan_logs").insert({
      target_id: targetId, log_type: "info",
      message: `🧠 Planner turn: ${actions.length} actions → ${queued} queued (trace ${traceId.slice(0, 8)})`,
      metadata: { kind: "agent_planner_turn", trace_id: traceId, actions_proposed: actions.length, queued, reasoning: reasoning.slice(0, 400) },
    });

    return new Response(JSON.stringify({
      ok: true, trace_id: traceId, actions_proposed: actions.length, queued, reasoning,
    }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (e) {
    console.error("agent-planner error", e);
    return new Response(JSON.stringify({ ok: false, error: (e as Error)?.message || String(e) }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" }, status: 200 });
  }
});
