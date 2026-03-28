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
        confidenceScore: 0,
        reasoning: "AI triage not configured",
      }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const prompt = `You are a Principal Security Engineer performing triage on a vulnerability finding.
Your job is to determine the TRUE confidence score (0-100%) that this is a REAL vulnerability, not a false positive.

Finding:
- Title: ${finding.title}
- Vulnerability Class: ${finding.vulnClass}
- Severity: ${finding.severity}
- Payload: ${finding.payload || "N/A"}
- Reachability: ${finding.reachabilityStatus || "unknown"}
- Execution Evidence: ${finding.executionEvidence || "none"}

Tech Stack: ${JSON.stringify(finding.techStack || {})}

Request Data: ${JSON.stringify(finding.requestData || {}).slice(0, 500)}
Response Data: ${JSON.stringify(finding.responseData || {}).slice(0, 500)}
Baseline Response: ${JSON.stringify(finding.baselineResponse || {}).slice(0, 300)}
Mutated Response: ${JSON.stringify(finding.mutatedResponse || {}).slice(0, 300)}

RULES:
- Score 90-100: Clear execution evidence (reflected payload, SQL errors, command output)
- Score 85-89: Strong differential response with corroborating indicators
- Score 50-84: Suspicious behavior but insufficient proof — needs manual review
- Score 0-49: Likely false positive (generic error, WAF response, no evidence)

Provide your confidence score and detailed reasoning about WHY this score.`;

    const resp = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${LOVABLE_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "google/gemini-2.5-flash",
        messages: [
          { role: "system", content: "You are a vulnerability triage specialist. Return structured results via the provided tool." },
          { role: "user", content: prompt },
        ],
        tools: [{
          type: "function",
          function: {
            name: "triage_result",
            description: "Return the triage classification result",
            parameters: {
              type: "object",
              properties: {
                confidenceScore: { type: "number", description: "0-100 confidence score" },
                reasoning: { type: "string", description: "Detailed reasoning for the score" },
              },
              required: ["confidenceScore", "reasoning"],
              additionalProperties: false,
            },
          },
        }],
        tool_choice: { type: "function", function: { name: "triage_result" } },
      }),
    });

    if (!resp.ok) {
      if (resp.status === 429) {
        return new Response(JSON.stringify({ error: "Rate limited" }), {
          status: 429, headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      if (resp.status === 402) {
        return new Response(JSON.stringify({ error: "Credits exhausted" }), {
          status: 402, headers: { ...corsHeaders, "Content-Type": "application/json" },
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
      confidenceScore: 50,
      reasoning: "AI returned unstructured response — defaulting to manual review",
    }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (e) {
    console.error("triage-brain error:", e);
    return new Response(JSON.stringify({
      error: e instanceof Error ? e.message : "Unknown error",
      confidenceScore: 0,
      reasoning: "Triage failed",
    }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
