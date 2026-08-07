import { defineTool } from "@lovable.dev/mcp-js";
import { z } from "zod";
import { supabaseForUser } from "../supabase";

export default defineTool({
  name: "create_target",
  title: "Create scan target",
  description: "Create a new target workspace to be scanned. Only in-scope, authorized targets should be added.",
  inputSchema: {
    name: z.string().trim().min(1).max(200).describe("Target name or primary URL/host."),
    auto_mythos: z.boolean().default(false).describe("Automatically run the full Mythos pipeline after creation."),
  },
  annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
  handler: async ({ name, auto_mythos }, ctx) => {
    if (!ctx.isAuthenticated()) {
      return { content: [{ type: "text", text: "Not authenticated" }], isError: true };
    }
    const supabase = supabaseForUser(ctx);
    const { data, error } = await supabase
      .from("target_workspaces")
      .insert({ name, auto_mythos, user_id: ctx.getUserId() })
      .select()
      .maybeSingle();
    if (error) return { content: [{ type: "text", text: error.message }], isError: true };
    return {
      content: [{ type: "text", text: JSON.stringify(data) }],
      structuredContent: { target: data },
    };
  },
});
