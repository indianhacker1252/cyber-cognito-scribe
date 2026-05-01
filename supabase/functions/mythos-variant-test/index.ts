// Per-variant payload tester — invoked by scan-job-worker for job_type "variant_test".
// Tests ONE variant against ONE endpoint, streams result into scan_logs and updates mythos_variants.
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { createEvidencePackage } from "../_shared/proof-packages.ts";
import { confirmFinding } from "../_shared/ai-confirm-gate.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

async function probe(url: string, payload: string, paramName = "q"): Promise<any> {
  try {
    const baseResp = await fetch(url, { signal: AbortSignal.timeout(6000), redirect: "manual" });
    const baseBody = await baseResp.text();
    const u = new URL(url);
    u.searchParams.set(paramName, payload);
    const t0 = Date.now();
    const r = await fetch(u.toString(), { signal: AbortSignal.timeout(8000), redirect: "manual" });
    const body = await r.text();
    const sqlError = /SQL syntax|mysql_|pg_query|SQLSTATE|ORA-|unclosed quotation/i.test(body) && !/SQL syntax|mysql_|pg_query|SQLSTATE|ORA-|unclosed quotation/i.test(baseBody);
    const sstiEval = /\b2674\b|\b49\b/.test(body) && !/\b2674\b|\b49\b/.test(baseBody) && !body.includes(payload);
    const cmdOutput = /cyberscope_marker|uid=\d+\(/.test(body) && !/cyberscope_marker|uid=\d+\(/.test(baseBody);
    const fileLeak = /root:.*:0:0|\/bin\/bash/.test(body) && !/root:.*:0:0|\/bin\/bash/.test(baseBody);
    const deterministicProof = sqlError || sstiEval || cmdOutput || fileLeak;
    return {
      status: r.status,
      baselineStatus: baseResp.status,
      bodyLen: body.length,
      baselineLen: baseBody.length,
      latencyMs: Date.now() - t0,
      reflected: body.includes(payload),
      errorSig: sqlError,
      deterministicProof,
      proofType: sqlError ? "sql_error" : sstiEval ? "template_eval" : cmdOutput ? "command_output" : fileLeak ? "file_leak" : "none",
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
    const isCandidate = result.deterministicProof;
    const status = result.status === 0 ? "error" : (isCandidate ? "candidate" : "negative");

    if (variantId) {
      await db.from("mythos_variants").update({
        test_endpoint: endpoint,
        test_status: status,
        test_result: result,
        is_zero_day_candidate: isCandidate,
      } as any).eq("id", variantId);
    }

    // Auto-promote only deterministic proof. Reflection-only candidates stay in Mythos for review.
    if (result.deterministicProof) {
      // ── AI confirmation + honeypot trap detector ──
      const gate = await confirmFinding({
        vulnClass: vulnClass || "unknown",
        payload,
        endpoint,
        parameter: paramName || "q",
        baseline: { status: result.baselineStatus, length: result.baselineLen, bodySnippet: "" },
        mutated: { status: result.status, length: result.bodyLen, bodySnippet: result.bodySnippet || "" },
        deterministicProof: true,
        proofType: result.proofType,
      });
      if (gate.recommendedAction === "drop_honeypot" || gate.recommendedAction === "drop_false_positive") {
        await db.from("scan_logs").insert({
          target_id: targetId, log_type: "info",
          message: `🍯 variant suppressed by AI gate: ${gate.reasoning}`,
          metadata: { variant_id: variantId, gate },
        });
        return new Response(JSON.stringify({ variantId, status: "suppressed", gate }),
          { headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      const findingPayload = {
        target_id: targetId,
        title: `🌀 0-Day Variant: ${vulnClass || "unknown"} via mutated payload`,
        severity: result.errorSig ? "critical" : "high",
        payload,
        cvss_score: result.errorSig ? 8.8 : 7.5,
        description: `Variant payload triggered deterministic proof (${result.proofType}) on ${endpoint}. Baseline ${result.baselineStatus}/${result.baselineLen}b → mutated ${result.status}/${result.bodyLen}b.\n\n**AI confirmation:** ${gate.reasoning}`,
        remediation: `Apply context-aware sanitization on parameter "${paramName || "q"}". Validate against schema/allowlist.`,
        confidence_score: gate.confidence,
        confidence_level: "high",
        validation_status: "ai_confirmed",
        ai_verified: true,
        reachability_status: "reachable",
        poc: `curl '${endpoint}?${paramName || "q"}=${encodeURIComponent(payload)}'`,
        triage_reasoning: `AI gate (${gate.proofType}): ${gate.reasoning}`,
      };

      const { data: insertedFinding } = await db.from("vulnerability_findings").insert(findingPayload).select("id").single();
      const evidenceId = await createEvidencePackage(db, {
        targetId,
        findingId: insertedFinding?.id || null,
        title: findingPayload.title,
        proofSummary: `Variant payload produced deterministic ${result.proofType} evidence on ${endpoint}. Baseline ${result.baselineStatus}/${result.baselineLen}B versus mutated ${result.status}/${result.bodyLen}B.`,
        remediation: findingPayload.remediation,
        request: {
          method: "GET",
          url: `${endpoint}?${paramName || "q"}=${encodeURIComponent(payload)}`,
          headers: { "User-Agent": "CyberScope-VariantTest/1.0" },
          payload,
          parameter: paramName || "q",
        },
        baselineResponse: { status: result.baselineStatus, length: result.baselineLen, body: null, bodySnippet: "Baseline body omitted by variant test" },
        mutatedResponse: { status: result.status, length: result.bodyLen, body: result.bodySnippet, bodySnippet: result.bodySnippet },
        validationStatus: "verified",
        pocScript: findingPayload.poc,
      });

      if (insertedFinding?.id && evidenceId) {
        await db.from("vulnerability_findings").update({ evidence_package_id: evidenceId }).eq("id", insertedFinding.id);
      }
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
