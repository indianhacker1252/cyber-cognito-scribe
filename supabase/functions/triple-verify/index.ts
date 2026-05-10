// triple-verify — orchestrator that takes a vulnerability_findings.id,
// runs the shared tripleVerify pipeline, and writes back:
//   confidence_score, validation_status (confirmed | needs_review | inconclusive),
//   triage_reasoning (human-readable), hard_evidence.triple_verify (raw stages)
//
// Always returns 200 OK. Errors land in JSON body so callers stay resilient.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { tripleVerify } from "../_shared/triple-verify.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

function inferVulnClass(title: string, payload: string): string {
  const t = (title + " " + payload).toLowerCase();
  if (/sql|sqli|union|select|or 1=1/.test(t)) return "sqli";
  if (/xss|<script|onerror|onload|<svg/.test(t)) return "rxss";
  if (/cmd|command|exec|;.*echo|\|.*echo/.test(t)) return "cmdi";
  if (/ssti|template|\{\{.*\}\}/.test(t)) return "ssti";
  if (/path[- ]?travers|lfi|\.\.\/|etc\/passwd/.test(t)) return "path-traversal";
  if (/ssrf|169\.254|metadata/.test(t)) return "ssrf";
  if (/xxe|xml.*entity/.test(t)) return "xxe";
  if (/redirect/.test(t)) return "open-redirect";
  return "unknown";
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

  const ok = (body: Record<string, unknown>) =>
    new Response(JSON.stringify(body), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });

  try {
    const { findingId } = await req.json().catch(() => ({}));
    if (!findingId || typeof findingId !== "string") {
      return ok({ ok: false, error: "findingId required" });
    }

    const db = createClient(SUPABASE_URL, SERVICE_KEY, { auth: { persistSession: false } });

    const { data: f, error: fErr } = await db
      .from("vulnerability_findings")
      .select("id, target_id, title, payload, endpoint_id, hard_evidence")
      .eq("id", findingId)
      .maybeSingle();
    if (fErr || !f) return ok({ ok: false, error: fErr?.message || "finding not found" });

    const { data: ep } = f.endpoint_id
      ? await db.from("discovered_endpoints").select("url, method, parameters, headers").eq("id", f.endpoint_id).maybeSingle()
      : { data: null };

    const url = ep?.url;
    if (!url) {
      // No endpoint — mark as needs_review since we can't independently verify
      await db.from("vulnerability_findings").update({
        validation_status: "needs_review",
        confidence_score: 50,
        triage_reasoning: "triple-verify skipped — no endpoint URL bound to finding; manual review required.",
      }).eq("id", findingId);
      return ok({ ok: true, tier: "needs_review", confidence: 50, reason: "no endpoint" });
    }

    const params = (ep?.parameters || {}) as Record<string, unknown>;
    const paramName = Object.keys(params)[0] || "id";
    const payload = f.payload || "<cyberscope>";
    const vulnClass = inferVulnClass(f.title || "", payload);

    const verifyRes = await tripleVerify({
      url,
      method: ep?.method || "GET",
      paramName,
      payload,
      cleanValue: "1",
      vulnClass,
    });

    const reasoning = `Triple-verify: ${verifyRes.summary}` +
      (verifyRes.reasons.length ? `\nReasons: ${verifyRes.reasons.join("; ")}` : "") +
      (verifyRes.errors.length ? `\nErrors: ${verifyRes.errors.join("; ")}` : "");

    await db.from("vulnerability_findings").update({
      validation_status: verifyRes.tier,
      confidence_score: verifyRes.confidence,
      triage_reasoning: reasoning,
      hard_evidence: { ...(f.hard_evidence as object || {}), triple_verify: verifyRes },
    }).eq("id", findingId);

    // Log to scan_logs for visibility
    await db.from("scan_logs").insert({
      target_id: f.target_id,
      log_type: "info",
      message: `🔬 Triple-verify [${verifyRes.tier}] confidence=${verifyRes.confidence}% — ${f.title}`,
      metadata: { findingId, summary: verifyRes.summary, signals: verifyRes.signals },
    });

    return ok({ ok: true, ...verifyRes });
  } catch (e) {
    return ok({ ok: false, error: e instanceof Error ? e.message : String(e) });
  }
});
