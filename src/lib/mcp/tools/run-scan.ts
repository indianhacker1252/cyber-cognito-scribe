import { defineTool } from "@lovable.dev/mcp-js";
import { z } from "zod";
import { supabaseForUser } from "../supabase";

export default defineTool({
  name: "run_scan",
  title: "Start a scan",
  description:
    "Kick off a new autonomous scan session for a target the signed-in user owns. Returns the agent_session id you can poll with explain_finding / list_findings.",
  inputSchema: {
    target_id: z.string().uuid().describe("Target to scan (must belong to the caller)."),
    mode: z
      .enum(["quick", "deep", "chain"])
      .default("deep")
      .describe("quick=recon+top-10, deep=full OWASP, chain=multi-step exploit chains."),
    max_iterations: z.number().int().min(1).max(50).default(12),
  },
  annotations: { readOnlyHint: false, idempotentHint: false, openWorldHint: true },
  handler: async ({ target_id, mode, max_iterations }, ctx) => {
    if (!ctx.isAuthenticated()) {
      return { content: [{ type: "text", text: "Not authenticated" }], isError: true };
    }
    const supabase = supabaseForUser(ctx);

    // Ownership check via RLS: the select will return 0 rows if the caller doesn't own the target.
    const { data: target, error: tErr } = await supabase
      .from("targets")
      .select("id,url")
      .eq("id", target_id)
      .maybeSingle();
    if (tErr) return { content: [{ type: "text", text: tErr.message }], isError: true };
    if (!target) {
      return { content: [{ type: "text", text: "Target not found or not authorized" }], isError: true };
    }

    const { data: session, error: sErr } = await supabase
      .from("agent_sessions")
      .insert({
        target_id,
        user_id: ctx.getUserId(),
        status: "queued",
        mode,
        max_iterations,
        trigger: "mcp",
      })
      .select("id,status,created_at")
      .single();
    if (sErr) return { content: [{ type: "text", text: sErr.message }], isError: true };

    return {
      content: [
        {
          type: "text",
          text: `Queued ${mode} scan for ${target.url}. session_id=${session.id}`,
        },
      ],
      structuredContent: { session_id: session.id, status: session.status, target_url: target.url },
    };
  },
});
