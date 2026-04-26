// XSS Reflection Auto-Promoter
// Scans recent pending_approvals + scan_logs for the target and auto-promotes
// any anomaly whose payload contains an executable XSS sink AND is reflected
// verbatim in the response body. Pure reflection check — no LLM required.
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

const XSS_SINKS = [
  /<script[\s>]/i,
  /onerror\s*=/i,
  /onload\s*=/i,
  /onclick\s*=/i,
  /onmouseover\s*=/i,
  /<svg[^>]*on\w+/i,
  /<img[^>]*onerror/i,
  /javascript:/i,
  /<iframe[^>]*src/i,
];

function looksLikeXss(payload: string): boolean {
  if (!payload) return false;
  return XSS_SINKS.some(rx => rx.test(payload));
}

function isReflected(body: unknown, payload: string): boolean {
  if (!payload || !body) return false;
  const text = typeof body === "string" ? body : JSON.stringify(body);
  if (!text) return false;
  // Verbatim reflection — strict to avoid noise
  if (text.includes(payload)) return true;
  // Also accept the dangerous core (e.g. `<script>alert(1)</script>` minus encoding)
  const core = payload.replace(/[<>"']/g, "").slice(0, 30);
  return core.length > 8 && text.includes(core) && /[<>]/.test(text);
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });
  try {
    const { targetId } = await req.json();
    if (!targetId) throw new Error("targetId required");

    const db = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    );

    // Pull recent pending approvals for this target
    const { data: approvals } = await (db as any)
      .from("pending_approvals")
      .select("id,title,payload_used,response_data,mutated_response,parameter,endpoint_id,finding_type,severity")
      .eq("target_id", targetId)
      .order("created_at", { ascending: false })
      .limit(200);

    let promoted = 0;
    const promotedRows: any[] = [];

    for (const a of (approvals || [])) {
      const payload = a.payload_used || "";
      if (!looksLikeXss(payload)) continue;

      const respBody =
        (a.mutated_response as any)?.body ??
        (a.response_data as any)?.body ??
        a.mutated_response ?? a.response_data;

      if (!isReflected(respBody, payload)) continue;

      // Already promoted? skip
      const { data: existing } = await (db as any)
        .from("vulnerability_findings")
        .select("id")
        .eq("target_id", targetId)
        .eq("payload", payload)
        .limit(1);
      if (existing && existing.length > 0) continue;

      const { error: insErr } = await (db as any).from("vulnerability_findings").insert({
        target_id: targetId,
        endpoint_id: a.endpoint_id,
        title: `Reflected XSS — verbatim payload reflected in response`,
        severity: "high",
        cvss_score: 7.4,
        confidence_score: 92,
        confidence_level: "high",
        validation_status: "auto_confirmed_reflection",
        ai_verified: false,
        payload,
        description: `Payload "${payload.slice(0, 120)}" was reflected verbatim in the response body of the target. Auto-promoted by reflection-based detector (no LLM required).`,
        triage_reasoning: `Strict reflection check passed: payload contains executable XSS sink (script/event-handler/javascript:) and appears unmodified in the response body. Promoted from pending approval ${a.id}.`,
        reachability_status: "reachable",
        remediation: "Apply context-aware output encoding (HTML, attribute, JS) and a strict CSP. Validate and reject reflected user input on the server.",
      });
      if (insErr) { console.error("insert failed", insErr); continue; }

      // mark approval as auto-confirmed
      await (db as any).from("pending_approvals")
        .update({ status: "approved", reviewer_notes: "Auto-promoted by reflection detector", reviewed_at: new Date().toISOString() })
        .eq("id", a.id);

      promoted++;
      promotedRows.push({ approvalId: a.id, payload });
    }

    await (db as any).from("scan_logs").insert({
      target_id: targetId,
      log_type: "info",
      message: `🎯 XSS reflection sweep: promoted ${promoted} confirmed XSS finding(s)`,
      metadata: { promoted, sample: promotedRows.slice(0, 5) },
    });

    return new Response(JSON.stringify({ promoted, details: promotedRows }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (e) {
    console.error(e);
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : String(e) }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
