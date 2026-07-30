// Enqueues a new agent_sessions row. The VPS runtime picks it up within ~3s.
import { createClient } from "npm:@supabase/supabase-js@2";
import { corsHeaders } from "npm:@supabase/supabase-js@2/cors";
import { z } from "npm:zod@3";

const Body = z.object({
  target_id: z.string().uuid(),
  goal: z.string().max(2000).optional(),
  provider: z.enum(["lovable", "openai", "gemini"]).default("lovable"),
  model: z.string().default("google/gemini-3.6-flash"),
  budget_credits: z.number().int().min(20).max(2000).default(200),
  budget_seconds: z.number().int().min(120).max(21600).default(3600),
});

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

  try {
    const auth = req.headers.get("Authorization");
    if (!auth) return json({ error: "missing_authorization" }, 401);

    const parsed = Body.safeParse(await req.json());
    if (!parsed.success) return json({ error: parsed.error.flatten() }, 400);

    const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
    const userClient = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_ANON_KEY")!, {
      global: { headers: { Authorization: auth } },
    });
    const { data: userData } = await userClient.auth.getUser();
    const userId = userData?.user?.id ?? null;

    // Refuse if a session is already running/queued for this target
    const { data: existing } = await admin
      .from("agent_sessions")
      .select("id,status")
      .eq("target_id", parsed.data.target_id)
      .in("status", ["queued", "running"])
      .maybeSingle();
    if (existing) return json({ error: "session_already_active", session_id: existing.id }, 409);

    const { data, error } = await admin.from("agent_sessions").insert({
      target_id: parsed.data.target_id,
      user_id: userId,
      goal: parsed.data.goal ?? null,
      model: parsed.data.model,
      provider: parsed.data.provider,
      budget_credits: parsed.data.budget_credits,
      budget_seconds: parsed.data.budget_seconds,
      status: "queued",
    }).select("*").single();

    if (error) return json({ error: error.message }, 500);

    // Flip target to agent-runtime mode
    await admin.from("target_workspaces").update({ use_agent_runtime: true }).eq("id", parsed.data.target_id);

    return json({ ok: true, session: data }, 200);
  } catch (e) {
    return json({ error: String((e as Error).message) }, 500);
  }
});

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}
