// Visual-diff judge — when mythos-debate returns 'inconclusive' on
// XSS/UI/DOM class, asks docker-worker for a baseline+payload screenshot
// pair and sends both to GPT vision via Lovable AI Gateway for a verdict.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};
function db() { return createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!); }

const VISION_CLASSES = ["xss", "dom_xss", "stored_xss", "reflected_xss", "ui_redress", "clickjacking", "open_redirect"];

async function dockerScreenshot(targetId: string, url: string, label: string): Promise<string | null> {
  const supa = db();
  const { data: cfg } = await supa.from("external_infra_config")
    .select("*").eq("service", "docker_worker").maybeSingle();
  if (!cfg?.is_active || !(cfg as any).endpoint_url) return null;
  try {
    const r = await fetch(`${(cfg as any).endpoint_url.replace(/\/$/, "")}/playwright`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...((cfg as any).auth_token ? { Authorization: `Bearer ${(cfg as any).auth_token}` } : {}),
      },
      body: JSON.stringify({ action: "screenshot", url, label }),
      signal: AbortSignal.timeout(20000),
    });
    if (!r.ok) return null;
    const j = await r.json();
    return j.screenshot_b64 || null; // expected contract
  } catch { return null; }
}

async function visionJudge(baselineB64: string, payloadB64: string, vulnClass: string, payload: string): Promise<any> {
  const key = Deno.env.get("LOVABLE_API_KEY");
  if (!key) return { verdict: "unknown", reason: "no LOVABLE_API_KEY" };
  try {
    const r = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${key}` },
      body: JSON.stringify({
        model: "google/gemini-2.5-flash",
        messages: [
          { role: "system", content: "You are a web-security judge. Compare a baseline page screenshot with a post-payload screenshot. Return STRICT JSON: { verdict: 'confirmed'|'false_positive'|'inconclusive', confidence: 0-100, reason: string }. Confirmed means the payload visibly executed (alert dialog, injected DOM, redirect, UI overlay). Differences in cosmetic data only = false_positive." },
          { role: "user", content: [
            { type: "text", text: `Vuln class: ${vulnClass}\nPayload: ${payload}\nBaseline (left) vs after-payload (right). Did the payload execute?` },
            { type: "image_url", image_url: { url: `data:image/png;base64,${baselineB64}` } },
            { type: "image_url", image_url: { url: `data:image/png;base64,${payloadB64}` } },
          ]},
        ],
      }),
      signal: AbortSignal.timeout(25000),
    });
    const j = await r.json();
    const txt = j.choices?.[0]?.message?.content || "{}";
    const jsonMatch = txt.match(/\{[\s\S]*\}/);
    return jsonMatch ? JSON.parse(jsonMatch[0]) : { verdict: "inconclusive", confidence: 0, reason: "no json" };
  } catch (e) {
    return { verdict: "inconclusive", confidence: 0, reason: e instanceof Error ? e.message : "vision err" };
  }
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const { targetId, debateId, vulnClass, baselineUrl, payloadUrl, payload } = await req.json();
    if (!VISION_CLASSES.includes((vulnClass || "").toLowerCase())) {
      return new Response(JSON.stringify({ ok: true, skipped: true, reason: "class not vision-eligible" }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const supa = db();
    const baselineB64 = await dockerScreenshot(targetId, baselineUrl, "baseline");
    const payloadB64 = await dockerScreenshot(targetId, payloadUrl, "payload");
    if (!baselineB64 || !payloadB64) {
      await supa.from("scan_logs").insert({
        target_id: targetId, log_type: "warning",
        message: "👁️ visual-diff-judge skipped: docker worker /playwright not available",
      } as any);
      return new Response(JSON.stringify({ ok: false, error: "no screenshots" }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const judgment = await visionJudge(baselineB64, payloadB64, vulnClass, payload || "");

    if (debateId) {
      await supa.from("mythos_debates").update({
        fp_verdict: judgment.verdict === "confirmed" ? "real" : judgment.verdict === "false_positive" ? "fp" : "unknown",
        fp_reasoning: `Visual-diff judge: ${judgment.reason}`,
        confidence_score: judgment.confidence || 0,
      }).eq("id", debateId);
    }

    await supa.from("scan_logs").insert({
      target_id: targetId, log_type: "result",
      message: `👁️ Visual-diff verdict for ${vulnClass}: ${judgment.verdict} (${judgment.confidence}%)`,
      metadata: { judgment, debateId },
    } as any);

    return new Response(JSON.stringify({ ok: true, judgment }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (e) {
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : "err" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
