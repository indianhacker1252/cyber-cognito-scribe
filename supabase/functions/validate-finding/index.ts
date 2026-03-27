import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

// Forbidden patterns - never execute scripts containing these
// These are narrowly scoped to avoid false positives on legitimate PoC scripts
const FORBIDDEN_PATTERNS = [
  /drop\s+table/i, /truncate\s+table/i, /delete\s+from/i, /rm\s+-rf/i,
  /shutdown/i, /xp_cmdshell/i,
  /os\.system\s*\(/i, /subprocess\.(call|run|Popen)\s*\(/i,
  /__import__\s*\(\s*['"]os['"]\)/i, /open\s*\(\s*['"]\/etc/i,
];

function isScriptSafe(script: string): { safe: boolean; reason?: string } {
  for (const pattern of FORBIDDEN_PATTERNS) {
    if (pattern.test(script)) {
      return { safe: false, reason: `Script contains forbidden pattern: ${pattern.source}` };
    }
  }
  return { safe: true };
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  try {
    const { findingId, approvalId, targetId, script, action } = await req.json();

    const db = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    );

    // Action: "validate" - simulate execution and generate report
    if (action === "validate") {
      if (!script) {
        return new Response(JSON.stringify({ error: "Script is required" }), {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      // Safety check
      const safety = isScriptSafe(script);
      if (!safety.safe) {
        return new Response(JSON.stringify({
          error: `Script failed safety validation: ${safety.reason}`,
          terminalOutput: `[SECURITY] Script rejected: ${safety.reason}\n[ABORT] Validation halted.`,
        }), {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      // Simulate validation execution with AI analysis
      const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
      let terminalOutput = "";
      let validationResult = "inconclusive";

      if (LOVABLE_API_KEY) {
        const resp = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${LOVABLE_API_KEY}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            model: "google/gemini-3-flash-preview",
            messages: [
              {
                role: "system",
                content: `You are a security validation engine. Analyze the provided PoC script and simulate what its output would look like if run against the target. Generate realistic terminal output showing:
1. Script initialization
2. Connection attempts
3. Test payloads being sent
4. Response analysis
5. A conclusion about whether the vulnerability is confirmed, likely, or inconclusive

Format the output exactly like a terminal session with timestamps. Be realistic but professional.`,
              },
              {
                role: "user",
                content: `Simulate the execution output of this validation script:\n\n${script}`,
              },
            ],
          }),
        });

        if (resp.ok) {
          const data = await resp.json();
          terminalOutput = data.choices?.[0]?.message?.content || "";
          
          // Determine result from output
          const lower = terminalOutput.toLowerCase();
          if (lower.includes("confirmed") || lower.includes("vulnerable") || lower.includes("verified")) {
            validationResult = "confirmed";
          } else if (lower.includes("likely") || lower.includes("potential")) {
            validationResult = "likely";
          } else {
            validationResult = "inconclusive";
          }
        }
      } else {
        terminalOutput = `[INFO] Validation engine initialized\n[WARN] AI analysis unavailable - manual review required\n[INFO] Script passed safety checks\n[INFO] Validation status: requires manual verification`;
        validationResult = "inconclusive";
      }

      // Store evidence package
      const { data: pkg, error: pkgError } = await db.from("evidence_packages").insert({
        finding_id: findingId || null,
        approval_id: approvalId || null,
        target_id: targetId,
        poc_script: script,
        script_language: "python",
        terminal_output: terminalOutput,
        validation_status: validationResult,
        http_request_data: { script_hash: btoa(script.slice(0, 100)) },
        validated_at: new Date().toISOString(),
      }).select().single();

      if (pkgError) throw pkgError;

      return new Response(JSON.stringify({
        terminalOutput,
        validationResult,
        evidencePackageId: pkg.id,
      }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // Action: "report" - generate compliance report
    if (action === "report") {
      const { data: pkg } = await db.from("evidence_packages").select("*").eq("id", findingId).single();
      if (!pkg) {
        return new Response(JSON.stringify({ error: "Evidence package not found" }), {
          status: 404,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
      if (!LOVABLE_API_KEY) {
        return new Response(JSON.stringify({ error: "AI not configured" }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      // Fetch the related finding for context
      let findingContext = "";
      if (pkg.finding_id) {
        const { data: f } = await db.from("vulnerability_findings").select("*, target_workspaces(name, domain)").eq("id", pkg.finding_id).single();
        if (f) {
          findingContext = `Title: ${f.title}\nSeverity: ${f.severity}\nCVSS: ${f.cvss_score}\nDescription: ${f.description}\nTarget: ${f.target_workspaces?.domain}`;
        }
      }
      if (pkg.approval_id) {
        const { data: a } = await db.from("pending_approvals").select("*, target_workspaces(name, domain)").eq("id", pkg.approval_id).single();
        if (a) {
          findingContext = `Title: ${a.title}\nSeverity: ${a.severity}\nCVSS: ${a.cvss_score}\nDescription: ${a.description}\nTarget: ${a.target_workspaces?.domain}`;
        }
      }

      const resp = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${LOVABLE_API_KEY}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model: "google/gemini-3-flash-preview",
          messages: [
            {
              role: "system",
              content: "You are a senior security compliance officer. Generate a professional remediation report in Markdown format following industry standards (OWASP, NIST). Include: Executive Summary, Technical Details, Steps to Reproduce, Impact Analysis, CVSS 3.1 Scoring, Recommended Remediation, and Timeline.",
            },
            {
              role: "user",
              content: `Generate a professional security remediation report based on the following validated finding:

${findingContext}

Validation Script Used:
${pkg.poc_script?.slice(0, 2000) || "N/A"}

Terminal Output:
${pkg.terminal_output?.slice(0, 2000) || "N/A"}

Validation Result: ${pkg.validation_status}`,
            },
          ],
        }),
      });

      if (!resp.ok) {
        if (resp.status === 429) return new Response(JSON.stringify({ error: "Rate limited" }), { status: 429, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        if (resp.status === 402) return new Response(JSON.stringify({ error: "Credits exhausted" }), { status: 402, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        throw new Error(`AI error: ${resp.status}`);
      }

      const data = await resp.json();
      const report = data.choices?.[0]?.message?.content || "Report generation failed.";

      // Update evidence package with report
      await db.from("evidence_packages").update({ report_markdown: report }).eq("id", pkg.id);

      return new Response(JSON.stringify({ report, evidencePackageId: pkg.id }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    return new Response(JSON.stringify({ error: "Invalid action. Use 'validate' or 'report'" }), {
      status: 400,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (e) {
    console.error("validate-finding error:", e);
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : "Unknown error" }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
