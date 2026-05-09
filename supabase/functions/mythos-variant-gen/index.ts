// Pillar 4: Zero-day variant generator from CVE root-cause patterns.
// MVP+: enqueues per-variant test jobs through scan_jobs (streams progress to Mythos tab).
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });
  try {
    const { targetId, runId, cveIds } = await req.json();
    if (!targetId) throw new Error("targetId required");

    const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

    await db.from("scan_logs").insert({
      target_id: targetId, log_type: "thought",
      message: `🌀 Variant Gen: pulling CVE root-cause patterns from intel feeds`,
      metadata: { phase: "variant-intel-pull", run_id: runId },
    });

    let intel: any[] = [];
    if (cveIds?.length) {
      const { data } = await db.from("intel_feeds").select("title,vulnerability_class,extracted_payloads,raw_summary,report_id").in("report_id", cveIds).limit(5);
      intel = data || [];
    } else {
      const { data } = await db.from("intel_feeds").select("title,vulnerability_class,extracted_payloads,raw_summary,report_id").eq("status", "processed").order("ingested_at", { ascending: false }).limit(5);
      intel = data || [];
    }

    const { data: endpoints } = await db.from("discovered_endpoints").select("url,method,parameters").eq("target_id", targetId).limit(20);

    const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
    if (!LOVABLE_API_KEY) throw new Error("LOVABLE_API_KEY not configured");

    await db.from("scan_logs").insert({
      target_id: targetId, log_type: "action",
      message: `🧬 Variant Gen: asking LLM for root-cause variants from ${intel.length} CVEs`,
      metadata: { phase: "variant-llm-call", run_id: runId },
    });

    const aiResp = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: `Bearer ${LOVABLE_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "google/gemini-2.5-flash",
        messages: [
          { role: "system", content: `You are a zero-day researcher. Generate variant payloads as CONCRETE HTTP ATTACK STRINGS ONLY.

Rules:
- variant_payload MUST be a raw injectable string, never a sentence or pseudocode.
- Valid examples: '../../../etc/passwd', '<svg onload=alert(1)>', "' OR 1=1--", '{{7*7}}', 'http://169.254.169.254/'
- Invalid: any sentence, any prose description, any pseudocode like create_symlink(...).
- If the attack cannot be expressed as a raw injectable string, skip it.
- variant_payload max length: 500 chars.

Given a known CVE, identify its ROOT-CAUSE PATTERN, then return 3-5 novel variant payloads targeting the same root cause class.` },
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
    // Bug #5 fix — drop LLM hallucinations that came back as prose/pseudocode.
    const isValidPayload = (p: unknown): p is string => {
      if (typeof p !== "string") return false;
      const s = p.trim();
      if (!s || s.length >= 500) return false;
      if (/^(an?\s|the\s)/i.test(s)) return false;
      if (/\battempts to\b|\bwill\s|\bshould\s|\bcan\s/i.test(s)) return false;
      if (/create_symlink|pseudocode/i.test(s)) return false;
      if (s.split(/\s+/).length > 12 && /[a-z]\s+[a-z]+\s+[a-z]+/i.test(s) && !/[<>'"`{}\\;|&=]/.test(s)) return false;
      return true;
    };
    const rawVariants = (args.variants || []).filter((v: any) => isValidPayload(v?.variant_payload));
    const variants = rawVariants.slice(0, 8);

    // Insert variants as "queued" — actual testing is queued as scan_jobs
    const variantRecords: any[] = [];
    for (const v of variants) {
      const ep = endpoints?.[0]?.url ?? null;
      const paramName = endpoints?.[0]?.parameters
        ? Object.keys(endpoints[0].parameters as Record<string, string>)[0] || "q"
        : "q";
      const { data: inserted } = await db.from("mythos_variants").insert({
        run_id: runId ?? null, target_id: targetId,
        parent_cve: v.parent_cve, vuln_class: v.vuln_class,
        root_cause_pattern: v.root_cause_pattern,
        variant_payload: v.variant_payload, variant_rationale: v.variant_rationale,
        test_endpoint: ep, test_status: "queued",
        test_result: {}, is_zero_day_candidate: false,
      }).select().single();
      if (inserted) variantRecords.push({ ...inserted, _paramName: paramName });
    }

    await db.from("scan_logs").insert({
      target_id: targetId, log_type: "result",
      message: `🧬 Variant Gen: ${variants.length} variants generated, queueing tests`,
      metadata: { phase: "variant-generated", run_id: runId, count: variants.length },
    });

    // Queue per-variant test jobs (streams results into Mythos tab as worker picks them up)
    const jobs = variantRecords
      .filter(v => v.test_endpoint)
      .map(v => ({
        target_id: targetId,
        job_type: "variant_test",
        priority: 6,
        payload: {
          variantId: v.id,
          payload: v.variant_payload,
          endpoint: v.test_endpoint,
          paramName: v._paramName,
          vulnClass: v.vuln_class,
        },
      }));
    if (jobs.length) await db.from("scan_jobs").insert(jobs);

    // Also run inline tests for first 3 (so we have immediate results without waiting for cron)
    let immediateCandidates = 0;
    for (const v of variantRecords.slice(0, 3)) {
      if (!v.test_endpoint) continue;
      try {
        const u = new URL(v.test_endpoint);
        u.searchParams.set(v._paramName, v.variant_payload);
        const r = await fetch(u.toString(), { signal: AbortSignal.timeout(6000) });
        const body = await r.text();
        const reflected = body.includes(v.variant_payload);
        const errorSig = /SQL|syntax error|stack trace|undefined|TypeError|fatal error/i.test(body);
        const isCand = reflected || errorSig;
        if (isCand) immediateCandidates++;
        await db.from("mythos_variants").update({
          test_status: isCand ? "candidate" : "negative",
          test_result: { status: r.status, bodyLen: body.length, reflected, errorSig },
          is_zero_day_candidate: isCand,
        } as any).eq("id", v.id);
      } catch { /* leave as queued */ }
    }

    await db.from("scan_logs").insert({
      target_id: targetId,
      log_type: immediateCandidates > 0 ? "result" : "info",
      message: `🌀 Variant Gen done: ${variants.length} variants, ${immediateCandidates} immediate 0-day candidates, ${jobs.length} queued for follow-up`,
      metadata: { phase: "variant-complete", run_id: runId, candidates: immediateCandidates, queued: jobs.length },
    });

    return new Response(JSON.stringify({ variantsCount: variants.length, candidates: immediateCandidates, queued: jobs.length }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (e) {
    console.error(e);
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : String(e) }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
