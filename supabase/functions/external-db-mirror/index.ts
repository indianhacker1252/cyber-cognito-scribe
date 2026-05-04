// External Postgres mirror: tests connection, initializes schema, and mirrors findings.
// Uses deno-postgres. Connection string supplied per-request (never stored in env).
import { Client } from "https://deno.land/x/postgres@v0.19.3/mod.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

const SCHEMA_SQL = `
create table if not exists cyberscope_findings (
  id uuid primary key,
  user_id uuid,
  target_id uuid,
  target_name text,
  title text,
  severity text,
  cvss_score numeric,
  confidence_score int,
  validation_status text,
  description text,
  payload text,
  poc text,
  remediation text,
  endpoint_url text,
  endpoint_method text,
  created_at timestamptz,
  mirrored_at timestamptz default now()
);
create index if not exists cyberscope_findings_target_idx on cyberscope_findings(target_id);
`;

function ok(body: any) { return new Response(JSON.stringify({ ok: true, ...body }), { headers: { ...corsHeaders, "Content-Type": "application/json" } }); }
function fail(error: string, extra: any = {}) { return new Response(JSON.stringify({ ok: false, error, ...extra }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }); }

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });
  let body: any;
  try { body = await req.json(); } catch { return fail("invalid json"); }
  const { action, connectionString, userId, findingIds } = body || {};
  let cs: string | undefined = connectionString;

  // If userId provided & no connection string, look it up
  if (!cs && userId) {
    const supa = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
    const { data } = await supa.from("external_db_config").select("pg_connection_string,enabled").eq("user_id", userId).maybeSingle();
    if (!data?.enabled || !data?.pg_connection_string) return fail("mirror not enabled");
    cs = data.pg_connection_string as string;
  }
  if (!cs) return fail("connection string required");

  let client: Client;
  try {
    client = new Client(cs);
    await client.connect();
  } catch (e: any) {
    return fail(`connect failed: ${e.message}`);
  }

  try {
    if (action === "test") {
      await client.queryArray(SCHEMA_SQL);
      const r = await client.queryObject<{ now: Date }>("select now()");
      return ok({ now: r.rows[0].now });
    }

    if (action === "mirror") {
      const supa = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
      const q = supa.from("vulnerability_findings").select("*, target_workspaces(name,domain), discovered_endpoints(url,method)");
      const { data: rows } = findingIds && findingIds.length
        ? await q.in("id", findingIds)
        : await q.limit(500);
      await client.queryArray(SCHEMA_SQL);
      let inserted = 0;
      for (const f of rows || []) {
        const ep = (f as any).discovered_endpoints;
        const tw = (f as any).target_workspaces;
        await client.queryObject(
          `insert into cyberscope_findings(id,user_id,target_id,target_name,title,severity,cvss_score,confidence_score,validation_status,description,payload,poc,remediation,endpoint_url,endpoint_method,created_at)
           values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
           on conflict (id) do update set mirrored_at=now(), validation_status=excluded.validation_status`,
          [f.id, userId || null, f.target_id, tw?.name || tw?.domain || null, f.title, f.severity, f.cvss_score, f.confidence_score, f.validation_status, f.description, f.payload, f.poc, f.remediation, ep?.url || null, ep?.method || null, f.created_at]
        );
        inserted++;
      }
      return ok({ mirrored: inserted });
    }

    return fail("unknown action");
  } catch (e: any) {
    return fail(e.message);
  } finally {
    try { await client.end(); } catch { /* ignore */ }
  }
});
