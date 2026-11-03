// runtime-gateway — brokers all VPS runtime agent DB access.
// The runtime cannot hold the service role key (Lovable Cloud never exposes it),
// so it authenticates here with a shared RUNTIME_SECRET and this function
// executes a whitelisted set of table operations with the service role.
import { createClient } from "npm:@supabase/supabase-js@2";
import { corsHeaders } from "npm:@supabase/supabase-js@2/cors";

const ALLOWED_TABLES = new Set([
  "agent_sessions",
  "agent_events",
  "tool_invocations",
  "target_workspaces",
  "target_world_model",
  "agent_experiences",
  "agent_metrics",
  "agent_auth_contexts",
  "endpoint_catalog",
  "agent_notes",
  "vulnerability_findings",
]);

const ALLOWED_RPCS = new Set(["claim_agent_session", "merge_world_model"]);

// table -> allowed write ops
const WRITE_RULES: Record<string, Set<string>> = {
  agent_sessions: new Set(["insert", "update"]),
  agent_events: new Set(["insert"]),
  tool_invocations: new Set(["insert"]),
  target_workspaces: new Set(["update"]),
  target_world_model: new Set(["update", "upsert"]),
  agent_experiences: new Set(["insert"]),
  agent_metrics: new Set(["insert"]),
  agent_auth_contexts: new Set(["upsert", "insert"]),
  endpoint_catalog: new Set(["upsert", "insert"]),
  agent_notes: new Set(["insert"]),
  vulnerability_findings: new Set(["insert"]),
};

type Filter = { op: "eq" | "in" | "ilike" | "overlaps" | "neq" | "gt" | "lt"; col: string; val: unknown };
type Order = { col: string; asc?: boolean };

type Body =
  | { op: "query"; table: string; select?: string; filters?: Filter[]; or?: string; order?: Order[]; limit?: number; single?: "maybe" | "one" }
  | { op: "insert"; table: string; rows: Record<string, unknown> | Record<string, unknown>[]; select?: string; single?: "maybe" | "one" }
  | { op: "upsert"; table: string; rows: Record<string, unknown> | Record<string, unknown>[]; onConflict?: string; count?: boolean; select?: string; single?: "maybe" | "one" }
  | { op: "update"; table: string; patch: Record<string, unknown>; filters?: Filter[] }
  | { op: "rpc"; fn: string; args?: Record<string, unknown> };

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

function applyFilters(q: any, filters: Filter[] = []) {
  for (const f of filters) {
    if (!f || typeof f.col !== "string" || !/^[a-zA-Z0-9_.]+$/.test(f.col)) continue;
    switch (f.op) {
      case "eq": q = q.eq(f.col, f.val); break;
      case "neq": q = q.neq(f.col, f.val); break;
      case "in": q = q.in(f.col, Array.isArray(f.val) ? f.val : [f.val]); break;
      case "ilike": q = q.ilike(f.col, String(f.val)); break;
      case "overlaps": q = q.overlaps(f.col, Array.isArray(f.val) ? f.val : [f.val]); break;
      case "gt": q = q.gt(f.col, f.val); break;
      case "lt": q = q.lt(f.col, f.val); break;
    }
  }
  return q;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

  try {
    const secret = Deno.env.get("RUNTIME_SECRET");
    if (!secret) return json({ error: "gateway_not_configured" }, 500);
    if (req.headers.get("x-runtime-secret") !== secret) return json({ error: "unauthorized" }, 401);

    const body = (await req.json()) as Body;
    const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

    if (body.op === "rpc") {
      if (!ALLOWED_RPCS.has(body.fn)) return json({ error: "rpc_not_allowed" }, 403);
      const { data, error } = await admin.rpc(body.fn, body.args ?? {});
      if (error) return json({ error: error.message }, 200);
      return json({ data }, 200);
    }

    const table = (body as { table?: string }).table;
    if (!table || !ALLOWED_TABLES.has(table)) return json({ error: "table_not_allowed" }, 403);

    if (body.op === "query") {
      let q: any = admin.from(table).select(body.select ?? "*");
      q = applyFilters(q, body.filters);
      if (body.or) q = q.or(body.or);
      for (const o of body.order ?? []) {
        if (/^[a-zA-Z0-9_.]+$/.test(o.col)) q = q.order(o.col, { ascending: o.asc !== false });
      }
      if (body.limit) q = q.limit(Math.min(body.limit, 500));
      if (body.single === "maybe") q = q.maybeSingle();
      else if (body.single === "one") q = q.single();
      const { data, error, count } = await q;
      if (error) return json({ error: error.message }, 200);
      return json({ data, count }, 200);
    }

    const writeOps = WRITE_RULES[table] ?? new Set<string>();
    if (!writeOps.has(body.op)) return json({ error: "write_not_allowed" }, 403);

    if (body.op === "insert") {
      let q: any = admin.from(table).insert(body.rows);
      if (body.select) q = q.select(body.select);
      if (body.single === "maybe") q = q.maybeSingle();
      else if (body.single === "one") q = q.single();
      const { data, error } = await q;
      if (error) return json({ error: error.message }, 200);
      return json({ data }, 200);
    }

    if (body.op === "upsert") {
      let q: any = admin.from(table).upsert(body.rows, {
        onConflict: body.onConflict,
        count: body.count ? "exact" : undefined,
      });
      if (body.select) q = q.select(body.select);
      if (body.single === "maybe") q = q.maybeSingle();
      const { data, error, count } = await q;
      if (error) return json({ error: error.message }, 200);
      return json({ data, count }, 200);
    }

    if (body.op === "update") {
      let q: any = admin.from(table).update(body.patch);
      q = applyFilters(q, body.filters);
      const { error } = await q;
      if (error) return json({ error: error.message }, 200);
      return json({ ok: true }, 200);
    }

    return json({ error: "unknown_op" }, 400);
  } catch (e) {
    return json({ error: String((e as Error).message) }, 500);
  }
});
