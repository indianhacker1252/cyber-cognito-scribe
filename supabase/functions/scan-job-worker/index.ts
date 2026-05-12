// Job queue worker — replaces the 50s edge timeout cap.
// pg_cron pings this every minute; it picks up to N queued jobs and dispatches
// them to the appropriate edge function (fire-and-forget with attempt tracking).
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

function db() { return createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!); }

const FN_BASE = `${Deno.env.get("SUPABASE_URL")}/functions/v1`;
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

const JOB_ROUTES: Record<string, string> = {
  recon: "recon-engine",
  fuzz: "advanced-fuzzer",
  oob: "oob-collector",
  browser: "headless-browser",
  browser_exploit: "browser-exploit",
  chain: "exploit-chain-runner",
  drift_canary: "canary-drift-monitor",
  json_fuzz: "json-fuzzer",
  cve: "cve-version-matcher",
  variant_test: "mythos-variant-test",
  debate: "mythos-debate",
  patch_validate: "mythos-patch-validate",
  exploit: "exploit-engine",
  proof: "proof-engine",
  mythos_step: "mythos-orchestrator",
};

async function runJob(job: any): Promise<{ ok: boolean; result?: any; error?: string }> {
  const route = JOB_ROUTES[job.job_type];
  if (!route) return { ok: false, error: `unknown job_type: ${job.job_type}` };
  try {
    const r = await fetch(`${FN_BASE}/${route}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${SERVICE_KEY}` },
      body: JSON.stringify({ targetId: job.target_id, ...job.payload }),
      signal: AbortSignal.timeout(45000),
    });
    const text = await r.text();
    let body: any = text;
    try { body = JSON.parse(text); } catch { /* keep text */ }
    return r.ok ? { ok: true, result: body } : { ok: false, error: `HTTP ${r.status}`, result: body };
  } catch (e) { return { ok: false, error: e instanceof Error ? e.message : "err" }; }
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const supa = db();
    const limit = 5;
    const { data: jobs } = await supa.from("scan_jobs")
      .select("*").eq("status", "queued").lte("next_run_at", new Date().toISOString())
      .order("priority", { ascending: false }).order("created_at").limit(limit);

    if (!jobs || jobs.length === 0) {
      return new Response(JSON.stringify({ picked: 0, message: "no queued jobs" }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const results: any[] = [];
    for (const job of jobs) {
      await supa.from("scan_jobs").update({
        status: "running", started_at: new Date().toISOString(), attempts: job.attempts + 1,
      }).eq("id", job.id);

      const out = await runJob(job);
      if (out.ok) {
        await supa.from("scan_jobs").update({
          status: "done", completed_at: new Date().toISOString(), result: out.result || {},
        }).eq("id", job.id);
      } else {
        const isFinal = job.attempts + 1 >= job.max_attempts;
        await supa.from("scan_jobs").update({
          status: isFinal ? "failed" : "queued",
          error_message: out.error,
          next_run_at: new Date(Date.now() + 60_000 * Math.pow(2, job.attempts)).toISOString(),
          completed_at: isFinal ? new Date().toISOString() : null,
        }).eq("id", job.id);
      }
      results.push({ id: job.id, type: job.job_type, ok: out.ok, error: out.error });
    }

    return new Response(JSON.stringify({ picked: jobs.length, results }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (e) {
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : "err" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
