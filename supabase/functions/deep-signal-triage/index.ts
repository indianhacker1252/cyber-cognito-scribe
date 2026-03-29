import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  try {
    const { finding } = await req.json();
    if (!finding) {
      return new Response(JSON.stringify({ error: "finding is required" }), {
        status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
    if (!LOVABLE_API_KEY) {
      return new Response(JSON.stringify({
        verdict: "manual_review",
        confidenceScore: 0,
        mathematicalConsistency: 0,
        evidenceChainValid: false,
        reasoning: "AI judge not configured",
        recommendations: ["Configure AI gateway"],
      }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const prompt = `You are a Principal Security Researcher acting as a SECONDARY JUDGE in a vulnerability triage pipeline (similar to Cantina's high-signal approach).

Your job is to review the COMPLETE EVIDENCE CHAIN and determine if a finding should be PROMOTED to the dashboard or DEMOTED as noise.

You must be MATHEMATICALLY RIGOROUS. Check for:
1. Statistical consistency: Does the response differential match expected behavior for this vuln class?
2. Evidence chain validity: Do the baseline vs mutated responses show CAUSAL relationship with the payload?
3. False positive indicators: Generic error pages, WAF responses, rate limiting artifacts
4. Reproduction confidence: Could another researcher reproduce this finding?

Finding Under Review:
- Title: ${finding.findingTitle}
- Vulnerability Class: ${finding.vulnClass}
- Severity: ${finding.severity}
- Current Confidence: ${finding.confidenceScore}%
- Payload: ${finding.payload || "N/A"}

Tech Stack: ${JSON.stringify(finding.techStack || {})}

Baseline Response: ${JSON.stringify(finding.baselineResponse || {}).slice(0, 600)}
Mutated Response: ${JSON.stringify(finding.mutatedResponse || {}).slice(0, 600)}

${finding.intruderResults ? `Intruder Results (${finding.intruderResults.length} payloads): ${JSON.stringify(finding.intruderResults).slice(0, 400)}` : "No intruder data"}
${finding.adaptationHistory ? `Adaptation History: ${JSON.stringify(finding.adaptationHistory).slice(0, 300)}` : "No adaptation history"}
${finding.executionEvidence ? `Execution Evidence: ${finding.executionEvidence}` : "No direct execution evidence"}

VERDICT RULES:
- "promote": Confidence >= 85%, evidence chain is mathematically valid, reproducible
- "demote": Confidence < 40%, evidence is noise, generic errors, or WAF artifacts
- "manual_review": Everything else — needs human expert analysis

Provide mathematicalConsistency as a 0-100 score measuring how statistically significant the differential is.`;

    const resp = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${LOVABLE_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "google/gemini-2.5-flash",
        messages: [
          { role: "system", content: "You are a mathematically rigorous vulnerability judge. Return structured verdicts via the provided tool. Be extremely strict — only promote findings with clear, reproducible evidence." },
          { role: "user", content: prompt },
        ],
        tools: [{
          type: "function",
          function: {
            name: "triage_verdict",
            description: "Return the deep signal triage verdict",
            parameters: {
              type: "object",
              properties: {
                verdict: { type: "string", enum: ["promote", "demote", "manual_review"] },
                confidenceScore: { type: "number", description: "0-100 final confidence" },
                mathematicalConsistency: { type: "number", description: "0-100 statistical significance" },
                evidenceChainValid: { type: "boolean" },
                reasoning: { type: "string", description: "Detailed reasoning" },
                recommendations: { type: "array", items: { type: "string" } },
              },
              required: ["verdict", "confidenceScore", "mathematicalConsistency", "evidenceChainValid", "reasoning", "recommendations"],
              additionalProperties: false,
            },
          },
        }],
        tool_choice: { type: "function", function: { name: "triage_verdict" } },
      }),
    });

    if (!resp.ok) {
      if (resp.status === 429) {
        return new Response(JSON.stringify({ error: "Rate limited" }), {
          status: 429, headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      throw new Error(`AI error: ${resp.status}`);
    }

    const data = await resp.json();
    const toolCall = data.choices?.[0]?.message?.tool_calls?.[0];

    if (toolCall) {
      const result = JSON.parse(toolCall.function.arguments);
      return new Response(JSON.stringify(result), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    return new Response(JSON.stringify({
      verdict: "manual_review",
      confidenceScore: 50,
      mathematicalConsistency: 0,
      evidenceChainValid: false,
      reasoning: "AI returned unstructured response",
      recommendations: ["Manual review required"],
    }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (e) {
    console.error("deep-signal-triage error:", e);
    return new Response(JSON.stringify({
      error: e instanceof Error ? e.message : "Unknown error",
      verdict: "manual_review",
      confidenceScore: 0,
      reasoning: "Triage failed",
    }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
