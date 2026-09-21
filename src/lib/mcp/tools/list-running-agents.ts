import { defineTool } from "@lovable.dev/mcp-js";
import { z } from "zod";
import { supabaseForUser } from "../supabase";

export default defineTool({
  name: "list_running_agents",
  title: "List running agent sessions",
  description: "List the caller's currently queued or running autonomous scan sessions.",
  inputSchema: {
    include_completed: z.boolean().default(false).describe("Also include completed/failed sessions."),
    limit: z.number().int().min(1).max(100).default(25),
  },
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
  handler: async ({ include_completed, limit }, ctx) => {
    if (!ctx.isAuthenticated()) {
      return { content: [{ type: "text", text: "Not authenticated" }], isError: true };
    }
    const supabase = supabaseForUser(ctx);
    let q = supabase
      .from("agent_sessions")
      .select("id,target_id,status,mode,created_at,updated_at,iteration,max_iterations")
      .order("created_at", { ascending: false })
      .limit(limit);
    if (!include_completed) q = q.in("status", ["queued", "running", "planning"]);
    const { data, error } = await q;
    if (error) return { content: [{ type: "text", text: error.message }], isError: true };
    return {
      content: [{ type: "text", text: JSON.stringify(data ?? []) }],
      structuredContent: { sessions: data ?? [] },
    };
  },
});
