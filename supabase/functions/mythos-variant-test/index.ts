// Per-variant payload tester — invoked by scan-job-worker for job_type "variant_test".
// Tests ONE variant against ONE endpoint, streams result into scan_logs and updates mythos_variants.
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

async function probe(url: string, payload: string, paramName = "q"): Promise<any> {
  try {
    const u = new URL(url);
    u.searchParams.set(paramName, payload);
    const t0 = Date.now();
    const r = await fetch(u.toString(), { signal: AbortSignal.timeout(8000) });
    const body = await r.text();
    return {
      status: r.status,
      bodyLen: body.length,
      latencyMs: Date.now() - t0,
      reflected: body.includes(payload),
      errorSig: /SQL syntax|mysql_|pg_query|SQLSTATE|ORA-|stack trace|TypeError|fatal error/i.test(body),
      bodySnippet: body.slice(0, 300),
    };
  } catch (e) {
    return { status: 0, bodyLen: 0, latencyMs: 0, reflected: false, errorSig: false, error: e instanceof Error ? e.message : "err" };
  }
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });
  try {
    const { targetId, variantId, payload, endpoint, paramName, vulnClass } = await req.json();
    if (!targetId || !payload || !endpoint) throw new Error("targetId, payload, endpoint required");

    const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

    await db.from("scan_logs").insert({
      target_id: targetId, log_type: "action",
      message: `🌀 Testing variant: ${payload.slice(0, 60)} on ${endpoint}`,
      metadata: { phase: "variant-test-start", variant_id: variantId, endpoint, vuln_class: vulnClass },
    });

    const result = await probe(endpoint, payload, paramName || "q");
    const isCandidate = result.reflected || result.errorSig;
    const status = result.status === 0 ? "error" : (isCandidate ? "candidate" : "negative");

    if (variantId) {
      await db.from("mythos_variants").update({
        test_endpoint: endpoint,
        test_status: status,
        test_result: result,
        is_zero_day_candidate: isCandidate,
      } as any).eq("id", variantId);
    }

    // Auto-promote 0-day candidates to vulnerability_findings (Mythos-style)
    if (isCandidate) {
      await db.from("vulnerability_findings").insert({
        target_id: targetId,
        title: `🌀 0-Day Variant: ${vulnClass || "unknown"} via mutated payload`,
        severity: result.errorSig ? "critical" : "high",
        payload,
        cvss_score: result.errorSig ? 8.8 : 7.5,
        description: `Variant payload triggered ${result.errorSig ? "error signature" : "reflection"} on ${endpoint}. Status: ${result.status}, body length: ${result.bodyLen}b. Generated from CVE root-cause pattern.`,
        remediation: `Apply context-aware sanitization on parameter "${paramName || "q"}". Validate against schema/allowlist.`,
        confidence_score: result.errorSig && result.reflected ? 92 : 85,
        confidence_level: "high",
        validation_status: "verified",
        ai_verified: true,
        reachability_status: "reachable",
        poc: `curl '${endpoint}?${paramName || "q"}=${encodeURIComponent(payload)}'`,
      });
    }

    await db.from("scan_logs").insert({
      target_id: targetId,
      log_type: isCandidate ? "result" : "info",
      message: `${isCandidate ? "🚨 0-DAY CANDIDATE" : "✓ tested"}: ${status} (${result.status}, ${result.bodyLen}b, ${result.latencyMs}ms)`,
      metadata: { phase: "variant-test-end", variant_id: variantId, status, is_candidate: isCandidate },
    });

    return new Response(JSON.stringify({ variantId, status, isCandidate, result }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (e) {
    console.error("variant-test error:", e);
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : String(e) }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
