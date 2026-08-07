import { defineTool } from "@lovable.dev/mcp-js";
import { z } from "zod";
import { supabaseForUser } from "../supabase";

export default defineTool({
  name: "list_findings",
  title: "List vulnerability findings",
  description: "List vulnerability findings the signed-in user can see, optionally filtered by target or severity.",
  inputSchema: {
    target_id: z.string().uuid().optional().describe("Restrict to one target workspace."),
    severity: z.enum(["info", "low", "medium", "high", "critical"]).optional(),
    limit: z.number().int().min(1).max(200).default(50),
  },
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
  handler: async ({ target_id, severity, limit }, ctx) => {
    if (!ctx.isAuthenticated()) {
      return { content: [{ type: "text", text: "Not authenticated" }], isError: true };
    }
    const supabase = supabaseForUser(ctx);
    let q = supabase
      .from("vulnerability_findings")
      .select("id,title,severity,vuln_type,target_id,created_at,confidence,status")
      .order("created_at", { ascending: false })
      .limit(limit);
    if (target_id) q = q.eq("target_id", target_id);
    if (severity) q = q.eq("severity", severity);
    const { data, error } = await q;
    if (error) return { content: [{ type: "text", text: error.message }], isError: true };
    return {
      content: [{ type: "text", text: JSON.stringify(data ?? []) }],
      structuredContent: { findings: data ?? [] },
    };
  },
});
