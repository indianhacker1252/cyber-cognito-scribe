import { defineTool } from "@lovable.dev/mcp-js";
import { z } from "zod";
import { supabaseForUser } from "../supabase";

export default defineTool({
  name: "explain_finding",
  title: "Explain a finding",
  description:
    "Return a human-readable explanation of one vulnerability finding: what it is, the proof oracle verdict, the request/response evidence, and remediation guidance.",
  inputSchema: {
    finding_id: z.string().uuid(),
  },
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
  handler: async ({ finding_id }, ctx) => {
    if (!ctx.isAuthenticated()) {
      return { content: [{ type: "text", text: "Not authenticated" }], isError: true };
    }
    const supabase = supabaseForUser(ctx);

    const { data: f, error } = await supabase
      .from("vulnerability_findings")
      .select("id,title,severity,vuln_type,cvss_score,description,recommendation,evidence,confidence,status,url,parameter,target_id,created_at")
      .eq("id", finding_id)
      .maybeSingle();
    if (error) return { content: [{ type: "text", text: error.message }], isError: true };
    if (!f) return { content: [{ type: "text", text: "Finding not found or not authorized" }], isError: true };

    const { data: proofs } = await supabase
      .from("proof_evidence")
      .select("oracle,verdict,detail,created_at")
      .eq("finding_id", finding_id)
      .order("created_at", { ascending: false })
      .limit(10);

    const lines = [
      `# ${f.title}`,
      `Severity: ${f.severity}  •  Type: ${f.vuln_type}  •  Confidence: ${f.confidence ?? "?"}%`,
      f.cvss_score ? `CVSS: ${f.cvss_score}` : "",
      f.url ? `URL: ${f.url}${f.parameter ? `  (param: ${f.parameter})` : ""}` : "",
      "",
      "## What it is",
      f.description ?? "(no description)",
      "",
      "## Proof oracle verdicts",
      (proofs ?? []).length === 0
        ? "(no oracle verdicts on record — treat as suspected only)"
        : (proofs ?? [])
            .map((p) => `- ${p.oracle}: ${p.verdict}${p.detail ? ` — ${JSON.stringify(p.detail).slice(0, 200)}` : ""}`)
            .join("\n"),
      "",
      "## Remediation",
      f.recommendation ?? "(no recommendation on record)",
    ]
      .filter(Boolean)
      .join("\n");

    return {
      content: [{ type: "text", text: lines }],
      structuredContent: {
        finding: {
          id: f.id,
          title: f.title,
          severity: f.severity,
          vuln_type: f.vuln_type,
          confidence: f.confidence,
          url: f.url,
          parameter: f.parameter,
          cvss_score: f.cvss_score,
          status: f.status,
        },
        proof_evidence: proofs ?? [],
      },
    };
  },
});
