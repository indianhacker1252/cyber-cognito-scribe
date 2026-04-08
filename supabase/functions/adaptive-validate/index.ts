import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  try {
    const { action, chainId, context, findingId, approvalId, targetId, payload } = await req.json();
    const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

    // ─── AI Provider Fallback ───
    interface AIProvider { name: string; url: string; key: string; model: string; }

    async function getProviders(): Promise<AIProvider[]> {
      const providers: AIProvider[] = [];
      const lovableKey = Deno.env.get("LOVABLE_API_KEY");
      if (lovableKey) {
        providers.push({ name: "lovable", url: "https://ai.gateway.lovable.dev/v1/chat/completions", key: lovableKey, model: "google/gemini-3-flash-preview" });
      }
      const { data: configs } = await db.from("ai_provider_config").select("provider, api_key, is_active, priority").eq("is_active", true).order("priority");
      for (const c of configs || []) {
        if (c.provider === "gemini") providers.push({ name: "gemini", url: "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions", key: c.api_key, model: "gemini-2.5-flash" });
        else if (c.provider === "openai") providers.push({ name: "openai", url: "https://api.openai.com/v1/chat/completions", key: c.api_key, model: "gpt-4o-mini" });
      }
      return providers;
    }

    async function callAI(body: Record<string, unknown>): Promise<Response> {
      const providers = await getProviders();
      for (const p of providers) {
        const resp = await fetch(p.url, {
          method: "POST",
          headers: { Authorization: `Bearer ${p.key}`, "Content-Type": "application/json" },
          body: JSON.stringify({ ...body, model: p.model }),
        });
        if (resp.ok) return resp;
        if (resp.status === 402 || resp.status === 429) { console.log(`${p.name} returned ${resp.status}, trying next...`); continue; }
        return resp;
      }
      throw new Error("All AI providers exhausted. Add API keys in Settings.");
    }

    // ACTION: "analyze"
    if (action === "analyze") {
      const resp = await callAI({
        messages: [
          {
            role: "system",
            content: `You are a security validation engine performing authorized compliance testing. Given a security test payload and a target context, simulate what would happen if the test were run against a filtered environment.

For each of up to 3 adaptation iterations, generate:
1. The simulated HTTP response (status code and brief body)
2. Whether the filter was navigated
3. Technical reasoning

Respond in JSON format:
{
  "initialResponse": { "statusCode": number, "body": "string", "length": number },
  "iterations": [
    {
      "adaptationName": "string",
      "statusCode": number,
      "body": "string",
      "length": number,
      "navigated": boolean,
      "reasoning": "string"
    }
  ],
  "filterClassification": "string",
  "overallResult": "verification_success" | "all_filtered",
  "technicalSummary": "string"
}`,
          },
          {
            role: "user",
            content: `Simulate adaptive validation for this security test:\n\nPayload: ${payload || "N/A"}\nTarget: ${targetId || "N/A"}\nFinding Context: ${JSON.stringify(context || {})}\n\nGenerate realistic simulation results for a compliance audit.`,
          },
        ],
      });

      if (!resp.ok) throw new Error(`AI error: ${resp.status}`);

      const data = await resp.json();
      let content = data.choices?.[0]?.message?.content || "";
      let simulation;
      try {
        const jsonMatch = content.match(/\{[\s\S]*\}/);
        simulation = jsonMatch ? JSON.parse(jsonMatch[0]) : { error: "Could not parse AI response" };
      } catch {
        simulation = { rawResponse: content };
      }

      return new Response(JSON.stringify({ simulation }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // ACTION: "generate-poc"
    if (action === "generate-poc") {
      const resp = await callAI({
        messages: [
          {
            role: "system",
            content: `You are a security compliance engineer. Generate a professional, non-destructive Python proof-of-concept script for authorized security auditing. The script must:
1. Include an X-CyberScope-Token header for audit trail identification
2. Be completely non-destructive (read-only verification)
3. Include proper error handling and timeout
4. Print clear output showing verification steps
5. Follow safe baseline protocols

Return ONLY the Python script, no markdown formatting.`,
          },
          {
            role: "user",
            content: `Generate a PoC script for this verified security gap:\n\n${JSON.stringify(context || {})}`,
          },
        ],
      });

      if (!resp.ok) throw new Error(`AI error: ${resp.status}`);

      const data = await resp.json();
      const script = data.choices?.[0]?.message?.content || "";
      return new Response(JSON.stringify({ script }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // ACTION: "report"
    if (action === "report") {
      const adaptationMethodology = (context?.adaptationSteps || [])
        .map((s: any) => `- Iteration ${s.iteration}: ${s.adaptationName} — ${s.description} → ${s.success ? "SUCCESS" : "FILTERED"} (${s.reasoning})`)
        .join("\n");

      const resp = await callAI({
        messages: [
          {
            role: "system",
            content: `You are a senior security compliance officer. Generate a professional Security Audit Report in Markdown format following OWASP and NIST standards. Include these sections:

1. **Executive Summary** — Brief overview of the finding
2. **Technical Details** — Vulnerability type, affected component, CVSS 3.1 score
3. **Validation Methodology** — How the system navigated environmental filters (the adaptation path)
4. **Steps to Reproduce** — Clear reproduction steps using the PoC script
5. **Impact Analysis** — Business and technical impact assessment
6. **CVSS 3.1 Scoring** — Detailed vector breakdown
7. **Recommended Remediation** — Specific, actionable fixes
8. **Timeline** — Discovery to verification timeline

Use professional, compliance-oriented language throughout.`,
          },
          {
            role: "user",
            content: `Generate a Security Audit Report:

Title: ${context?.title || "N/A"}
Severity: ${context?.severity || "N/A"}
CVSS: ${context?.cvssScore || "N/A"}
Target: ${context?.targetDomain || "N/A"}
Description: ${context?.description || "N/A"}
Filter Classification: ${context?.filterClassification || "N/A"}
Verification Status: ${context?.verificationStatus || "N/A"}

Validation Methodology (Adaptation Path):
${adaptationMethodology || "No adaptations recorded."}

Technical Evidence Script:
${context?.pocScript?.slice(0, 2000) || "N/A"}`,
          },
        ],
      });

      if (!resp.ok) throw new Error(`AI error: ${resp.status}`);

      const data = await resp.json();
      const report = data.choices?.[0]?.message?.content || "Report generation failed.";

      if (chainId) {
        await db.from("adaptation_chains").update({ audit_report_markdown: report }).eq("id", chainId);
      }

      return new Response(JSON.stringify({ report }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    return new Response(JSON.stringify({ error: "Invalid action. Use 'analyze', 'generate-poc', or 'report'" }), {
      status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (e) {
    console.error("adaptive-validate error:", e);
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : "Unknown error" }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
