// Pillar 2: Autonomous exploit-chain discoverer
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });
  try {
    const { targetId, runId } = await req.json();
    if (!targetId) throw new Error("targetId required");

    const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

    const [findings, endpoints, codeFindings, pending] = await Promise.all([
      db.from("vulnerability_findings").select("id,title,severity,vuln_class:title,payload,description").eq("target_id", targetId).limit(40),
      db.from("discovered_endpoints").select("url,method,parameters").eq("target_id", targetId).limit(40),
      db.from("code_findings").select("vuln_class,file_path,severity").eq("target_id", targetId).limit(20),
      db.from("pending_approvals").select("title,severity,finding_type,payload_used").eq("target_id", targetId).limit(20),
    ]);

    const totalSignals = (findings.data?.length || 0) + (codeFindings.data?.length || 0) + (pending.data?.length || 0);
    if (totalSignals < 2) {
      await db.from("scan_logs").insert({
        target_id: targetId, log_type: "info",
        message: `🔗 Chainer skipped: only ${totalSignals} signal(s); need ≥2 to chain`,
        metadata: { phase: "chainer-skip", run_id: runId },
      });
      return new Response(JSON.stringify({ chainsCount: 0, skipped: true, reason: "insufficient signals" }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
    if (!LOVABLE_API_KEY) {
      await db.from("scan_logs").insert({
        target_id: targetId, log_type: "warning",
        message: `🔗 Chainer skipped: LOVABLE_API_KEY missing`,
        metadata: { phase: "chainer-no-key", run_id: runId },
      });
      return new Response(JSON.stringify({ chainsCount: 0, skipped: true, reason: "no LLM key" }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const aiResp = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: `Bearer ${LOVABLE_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "google/gemini-2.5-flash",
        messages: [
          { role: "system", content: "You are an elite offensive security researcher (think Mythos/AIxCC). Given findings + endpoints + SAST results, propose multi-stage exploit chains where each step's output enables the next. Each chain should be a realistic kill-chain (e.g. info-leak → auth bypass → RCE). Return 1-4 chains, max." },
          { role: "user", content: `Target findings:\n${JSON.stringify(findings.data || []).slice(0, 3500)}\n\nPending suspicions:\n${JSON.stringify(pending.data || []).slice(0, 1500)}\n\nEndpoints:\n${JSON.stringify(endpoints.data || []).slice(0, 1500)}\n\nSAST taint flows:\n${JSON.stringify(codeFindings.data || []).slice(0, 1500)}\n\nProduce kill-chains.` },
        ],
        tools: [{
          type: "function", function: {
            name: "propose_chains",
            description: "Return discovered exploit chains",
            parameters: {
              type: "object",
              properties: {
                chains: {
                  type: "array",
                  items: {
                    type: "object",
                    properties: {
                      name: { type: "string" },
                      narrative: { type: "string", description: "How attacker walks the chain" },
                      severity: { type: "string", enum: ["medium", "high", "critical"] },
                      cvss: { type: "number" },
                      finding_ids: { type: "array", items: { type: "string" } },
                      steps: {
                        type: "array",
                        items: {
                          type: "object",
                          properties: {
                            order: { type: "number" },
                            action: { type: "string" },
                            endpoint: { type: "string" },
                            extracts: { type: "string", description: "What this step yields for next step" },
                          }, required: ["order", "action", "endpoint", "extracts"], additionalProperties: false,
                        },
                      },
                    },
                    required: ["name", "narrative", "severity", "cvss", "finding_ids", "steps"], additionalProperties: false,
                  },
                },
              },
              required: ["chains"], additionalProperties: false,
            },
          },
        }],
        tool_choice: { type: "function", function: { name: "propose_chains" } },
      }),
    });

    if (!aiResp.ok) throw new Error(`AI ${aiResp.status}`);
    const aiData = await aiResp.json();
    const args = JSON.parse(aiData.choices?.[0]?.message?.tool_calls?.[0]?.function?.arguments || "{}");
    const chains = args.chains || [];

    const inserts = chains.map((c: any) => ({
      run_id: runId ?? null,
      target_id: targetId,
      chain_name: c.name,
      chain_narrative: c.narrative,
      steps: c.steps,
      finding_ids: c.finding_ids,
      combined_severity: c.severity,
      combined_cvss: c.cvss,
      execution_status: "proposed",
    }));
    if (inserts.length) await db.from("mythos_chains").insert(inserts);

    await db.from("scan_logs").insert({
      target_id: targetId, log_type: "warning",
      message: `🔗 Mythos Chainer: discovered ${chains.length} multi-stage exploit chains`,
      metadata: { chains: chains.map((c: any) => c.name) },
    });

    return new Response(JSON.stringify({ chainsCount: chains.length, chains }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (e) {
    console.error(e);
    return new Response(JSON.stringify({ chainsCount: 0, error: e instanceof Error ? e.message : String(e) }), {
      status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
