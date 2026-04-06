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
    const { messages, targetId } = await req.json();
    const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
    if (!LOVABLE_API_KEY) {
      return new Response(JSON.stringify({ error: "AI not configured" }), {
        status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // Gather context from DB for the AI
    const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

    let contextBlock = "";

    if (targetId) {
      const [findingsRes, approvalsRes, logsRes, endpointsRes] = await Promise.all([
        db.from("vulnerability_findings").select("title, severity, confidence_score, validation_status, triage_reasoning, payload").eq("target_id", targetId).order("created_at", { ascending: false }).limit(20),
        db.from("pending_approvals").select("title, severity, confidence_score, finding_type, ai_verified, triage_reasoning").eq("target_id", targetId).order("created_at", { ascending: false }).limit(15),
        db.from("scan_logs").select("message, log_type, created_at").eq("target_id", targetId).order("created_at", { ascending: false }).limit(30),
        db.from("discovered_endpoints").select("url, method, parameters").eq("target_id", targetId).limit(30),
      ]);

      const findings = findingsRes.data || [];
      const approvals = approvalsRes.data || [];
      const logs = logsRes.data || [];
      const endpoints = endpointsRes.data || [];

      contextBlock = `
## Current Scan Context (Target ID: ${targetId})

### Confirmed Findings (${findings.length}):
${findings.map(f => `- [${f.severity?.toUpperCase()}] ${f.title} (score: ${f.confidence_score || 'N/A'}, status: ${f.validation_status || 'pending'})${f.triage_reasoning ? ` — ${f.triage_reasoning.slice(0, 100)}` : ''}`).join("\n")}

### Pending Approvals (${approvals.length}):
${approvals.map(a => `- [${a.severity?.toUpperCase()}] ${a.title} (type: ${a.finding_type}, AI verified: ${a.ai_verified ? 'Yes' : 'No'}, score: ${a.confidence_score || 'N/A'})`).join("\n")}

### Discovered Endpoints (${endpoints.length}):
${endpoints.slice(0, 15).map(e => `- ${e.method} ${e.url} params=${JSON.stringify(e.parameters || {})}`).join("\n")}

### Recent Scan Logs:
${logs.slice(0, 15).map(l => `[${l.log_type}] ${l.message}`).join("\n")}
`;
    }

    const systemPrompt = `You are CyberScope AI — a Principal VAPT (Vulnerability Assessment & Penetration Testing) Analyst embedded in a live scanning platform.

You have deep knowledge of:
- OWASP Top 10 (2021) with practical exploitation techniques
- CVE analysis, CVSS scoring, and backport detection
- Web application penetration testing methodology
- False positive elimination and differential analysis
- WAF bypass, payload mutation, and adaptive fuzzing
- SecLists payload selection and context-aware testing
- Proof-of-Concept generation (Python/curl)
- Network reconnaissance and attack surface mapping

${contextBlock}

Answer questions about findings, suggest next steps, explain vulnerabilities, generate PoC scripts, or help with remediation. Be technical and precise. Use code blocks for payloads/scripts.`;

    const response = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${LOVABLE_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "google/gemini-3-flash-preview",
        messages: [
          { role: "system", content: systemPrompt },
          ...messages,
        ],
        stream: true,
      }),
    });

    if (!response.ok) {
      if (response.status === 429) {
        return new Response(JSON.stringify({ error: "Rate limited — try again shortly" }), {
          status: 429, headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      if (response.status === 402) {
        return new Response(JSON.stringify({ error: "Credits exhausted — add funds in Settings" }), {
          status: 402, headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      throw new Error(`AI error: ${response.status}`);
    }

    return new Response(response.body, {
      headers: { ...corsHeaders, "Content-Type": "text/event-stream" },
    });
  } catch (e) {
    console.error("vapt-chat error:", e);
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : "Unknown error" }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
