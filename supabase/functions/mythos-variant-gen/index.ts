// Pillar 4: Zero-day variant generator from CVE root-cause patterns
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

async function testPayload(url: string, payload: string): Promise<{ status: number; bodyLen: number; reflected: boolean; errorSig: boolean }> {
  try {
    const u = new URL(url);
    u.searchParams.set("q", payload);
    const r = await fetch(u.toString(), { signal: AbortSignal.timeout(8000) });
    const body = await r.text();
    return {
      status: r.status,
      bodyLen: body.length,
      reflected: body.includes(payload),
      errorSig: /SQL|syntax error|stack trace|undefined|TypeError|fatal error/i.test(body),
    };
  } catch {
    return { status: 0, bodyLen: 0, reflected: false, errorSig: false };
  }
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });
  try {
    const { targetId, runId, cveIds } = await req.json();
    if (!targetId) throw new Error("targetId required");

    const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

    let intel: any[] = [];
    if (cveIds?.length) {
      const { data } = await db.from("intel_feeds").select("title,vulnerability_class,extracted_payloads,raw_summary,report_id").in("report_id", cveIds).limit(5);
      intel = data || [];
    } else {
      const { data } = await db.from("intel_feeds").select("title,vulnerability_class,extracted_payloads,raw_summary,report_id").eq("status", "processed").order("ingested_at", { ascending: false }).limit(5);
      intel = data || [];
    }

    const { data: endpoints } = await db.from("discovered_endpoints").select("url,method").eq("target_id", targetId).limit(10);

    const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
    if (!LOVABLE_API_KEY) throw new Error("LOVABLE_API_KEY not configured");

    const aiResp = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: `Bearer ${LOVABLE_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "google/gemini-2.5-flash",
        messages: [
          { role: "system", content: "You are a zero-day researcher. Given a known CVE, identify its ROOT-CAUSE PATTERN (not the specific payload), then generate 3-5 *novel variant payloads* targeting the same root cause class. These variants should bypass naive patches and find UNDISCLOSED bugs in similar code paths." },
          { role: "user", content: `Known intel:\n${JSON.stringify(intel).slice(0, 4000)}\n\nGenerate variants.` },
        ],
        tools: [{
          type: "function", function: {
            name: "generate_variants",
            description: "Return zero-day variant payloads",
            parameters: {
              type: "object",
              properties: {
                variants: {
                  type: "array",
                  items: {
                    type: "object",
                    properties: {
                      parent_cve: { type: "string" },
                      vuln_class: { type: "string" },
                      root_cause_pattern: { type: "string" },
                      variant_payload: { type: "string" },
                      variant_rationale: { type: "string" },
                    },
                    required: ["parent_cve", "vuln_class", "root_cause_pattern", "variant_payload", "variant_rationale"],
                    additionalProperties: false,
                  },
                },
              },
              required: ["variants"], additionalProperties: false,
            },
          },
        }],
        tool_choice: { type: "function", function: { name: "generate_variants" } },
      }),
    });

    if (!aiResp.ok) throw new Error(`AI ${aiResp.status}`);
    const aiData = await aiResp.json();
    const args = JSON.parse(aiData.choices?.[0]?.message?.tool_calls?.[0]?.function?.arguments || "{}");
    const variants = (args.variants || []).slice(0, 8);

    const records: any[] = [];
    for (const v of variants) {
      const ep = endpoints?.[0]?.url;
      let testStatus = "untested";
      let testResult: any = {};
      let isZeroDay = false;
      if (ep) {
        const r = await testPayload(ep, v.variant_payload);
        testResult = r;
        testStatus = r.status === 0 ? "error" : (r.reflected || r.errorSig ? "candidate" : "negative");
        isZeroDay = r.reflected || r.errorSig;
      }
      records.push({
        run_id: runId ?? null, target_id: targetId, parent_cve: v.parent_cve,
        vuln_class: v.vuln_class, root_cause_pattern: v.root_cause_pattern,
        variant_payload: v.variant_payload, variant_rationale: v.variant_rationale,
        test_endpoint: ep ?? null, test_status: testStatus, test_result: testResult,
        is_zero_day_candidate: isZeroDay,
      });
    }

    if (records.length) await db.from("mythos_variants").insert(records);

    const candidates = records.filter(r => r.is_zero_day_candidate).length;
    await db.from("scan_logs").insert({
      target_id: targetId, log_type: candidates > 0 ? "warning" : "info",
      message: `🌀 Mythos Variant Gen: ${variants.length} variants tested, ${candidates} zero-day candidates`,
      metadata: { variants: variants.length, candidates },
    });

    return new Response(JSON.stringify({ variantsCount: variants.length, candidates, variants: records }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (e) {
    console.error(e);
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : String(e) }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
