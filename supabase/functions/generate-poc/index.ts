import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

function respond(ok: boolean, payload: Record<string, unknown>): Response {
  return new Response(JSON.stringify({ ok, ...payload }), {
    status: 200,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  try {
    const { findingId, approvalId } = await req.json();
    if (!findingId && !approvalId) {
      return respond(false, { error: "findingId or approvalId required" });
    }

    const db = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    );

    let finding: any = null;
    let approval: any = null;

    if (approvalId) {
      const { data } = await db.from("pending_approvals").select("*, target_workspaces(name, domain)").eq("id", approvalId).single();
      approval = data;
    }

    if (findingId) {
      const { data } = await db.from("vulnerability_findings").select("*, target_workspaces(name, domain)").eq("id", findingId).single();
      finding = data;
    }

    const source = approval || finding;
    if (!source) {
      return respond(false, { error: "Finding not found" });
    }

    const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
    if (!LOVABLE_API_KEY) {
      return respond(false, { error: "AI not configured. Add API key in Settings.", diagnostics: { error_stage: "ai_config" } });
    }

    const domain = source.target_workspaces?.domain || "target.example.com";
    const prompt = `You are a senior security auditor. Generate a clean, standalone Python proof-of-concept script that safely validates the following security finding WITHOUT causing any damage.

Finding: ${source.title}
Severity: ${source.severity}
Type: ${source.finding_type || "vulnerability"}
Description: ${source.description || "N/A"}
Parameter: ${source.parameter || "N/A"}
Payload Used: ${source.payload_used || "N/A"}
Target Domain: ${domain}
CVSS Score: ${source.cvss_score || "N/A"}

Requirements:
- Use Python 'requests' library
- Include clear comments explaining each step
- The script should only VERIFY the vulnerability exists (read-only, non-destructive)
- Print clear output indicating whether the vulnerability was confirmed
- Include proper error handling
- Add a safety banner at the top
- NEVER include destructive payloads (no DROP TABLE, rm -rf, etc.)
- Script should be self-contained and runnable

Return ONLY the Python script, no markdown fences.`;

    const resp = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${LOVABLE_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "google/gemini-3.8-flash",
        messages: [
          { role: "system", content: "You are a professional penetration tester writing safe, non-destructive PoC validation scripts. Return only executable Python code." },
          { role: "user", content: prompt },
        ],
      }),
    });

    if (!resp.ok) {
      const status = resp.status;
      if (status === 429) {
        return respond(false, { error: "Rate limited. Please try again in a few seconds.", diagnostics: { error_stage: "rate_limit" } });
      }
      if (status === 402) {
        return respond(false, { error: "AI credits exhausted. Please add funds in Settings → Usage.", diagnostics: { error_stage: "credits" } });
      }
      return respond(false, { error: `AI gateway error: ${status}`, diagnostics: { error_stage: "ai_gateway", status } });
    }

    const data = await resp.json();
    let script = data.choices?.[0]?.message?.content || "";

    // Clean up markdown fences if present
    script = script.replace(/^```python\n?/m, "").replace(/^```\n?/m, "").replace(/```$/m, "").trim();

    return respond(true, { script, language: "python", finding: source });
  } catch (e) {
    console.error("generate-poc error:", e);
    return respond(false, { error: e instanceof Error ? e.message : "Unknown error", diagnostics: { error_stage: "exception" } });
  }
});
