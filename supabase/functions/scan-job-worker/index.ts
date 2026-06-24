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
  template: "template-runner",
  owasp_template: "template-runner",
  patch_validate: "mythos-patch-validate",
  exploit: "exploit-engine",
  proof: "proof-engine",
  mythos_step: "mythos-orchestrator",
  browser_verify: "browser-exploit",
  chain_exec: "exploit-chain-runner",
  mutate: "request-mutator",
  local_tool: "local-worker-proxy",
  ollama_mutate: "local-worker-proxy",
  llm_attack: "llm-attack-suite",
  nvd_sync: "nvd-intel-sync",
};

async function runJob(job: any): Promise<{ ok: boolean; result?: any; error?: string }> {
  const route = JOB_ROUTES[job.job_type];
  if (!route) return { ok: false, error: `unknown job_type: ${job.job_type}` };
  // FIX: dedup fuzz jobs per target — prevents 10+ concurrent fuzzers on same target
  if (job.job_type === "fuzz" || job.job_type === "template") {
    const supa = db();
    const { count } = await supa.from("scan_jobs")
      .select("id", { count: "exact", head: true })
      .eq("target_id", job.target_id)
      .eq("job_type", job.job_type)
      .eq("status", "running");
    if ((count ?? 0) > 0) {
      // Defer 30s instead of running duplicate
      await supa.from("scan_jobs").update({
        status: "queued",
        next_run_at: new Date(Date.now() + 30_000).toISOString(),
      }).eq("id", job.id);
      return { ok: true, result: { deferred: true, reason: "duplicate_running" } };
    }
  }
  try {
    const modePayload = job.job_type === "ollama_mutate" ? { mode: "ai" } : job.job_type === "local_tool" ? { mode: "tool" } : {};
    const r = await fetch(`${FN_BASE}/${route}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${SERVICE_KEY}` },
      body: JSON.stringify({ targetId: job.target_id, ...modePayload, ...job.payload }),
      signal: AbortSignal.timeout(45000),
    });
    const text = await r.text();
    let body: any = text;
    try { body = JSON.parse(text); } catch { /* keep text */ }
    return r.ok ? { ok: true, result: body } : { ok: false, error: `HTTP ${r.status}`, result: body };
  } catch (e) { return { ok: false, error: e instanceof Error ? e.message : "err" }; }
}

async function sweepStuck(supa: any) {
  // Any job marked running >10min is presumed dead → requeue or fail.
  const cutoff = new Date(Date.now() - 10 * 60_000).toISOString();
  const { data: stuck } = await supa.from("scan_jobs")
    .select("id, attempts, max_attempts, target_id, job_type")
    .eq("status", "running").lt("started_at", cutoff).limit(20);
  for (const j of stuck || []) {
    const isFinal = j.attempts >= j.max_attempts;
    await supa.from("scan_jobs").update({
      status: isFinal ? "failed" : "queued",
      error_message: "stuck >10min — auto-recovered",
      next_run_at: new Date().toISOString(),
      completed_at: isFinal ? new Date().toISOString() : null,
    }).eq("id", j.id);
    await supa.from("scan_logs").insert({
      target_id: j.target_id, log_type: "warn",
      message: `⏱️ Job ${j.job_type} stuck >10min, ${isFinal ? "failed" : "requeued"}`,
      metadata: { kind: "stuck_job_sweep", job_id: j.id },
    });
  }
}

function detectCreditExhaustion(result: any, error?: string): boolean {
  const blob = JSON.stringify(result || {}) + " " + (error || "");
  return /402|credits.{0,20}exhaust|insufficient.{0,20}credit|bllmerror|AI credits/i.test(blob);
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const supa = db();
    await sweepStuck(supa).catch(() => {});

    // 🛑 Defensive gate: drop mythos_step jobs whose run is not 'running'.
    // Stops legacy orchestrator code from cascading against dead/paused/failed runs.
    {
      const { data: queuedSteps } = await supa.from("scan_jobs")
        .select("id, payload").eq("status", "queued").eq("job_type", "mythos_step").limit(2000);
      const runIds = [...new Set((queuedSteps || []).map((j: any) => j.payload?.runId).filter(Boolean))];
      if (runIds.length) {
        const { data: liveRuns } = await supa.from("mythos_runs")
          .select("id").in("id", runIds).eq("status", "running");
        const liveSet = new Set((liveRuns || []).map((r: any) => r.id));
        const deadIds = (queuedSteps || []).filter((j: any) => !liveSet.has(j.payload?.runId)).map((j: any) => j.id);
        if (deadIds.length) {
          await supa.from("scan_jobs").delete().in("id", deadIds);
          console.log(`gate: dropped ${deadIds.length} mythos_step jobs for non-running runs`);
        }
      }
    }

    // 🛑 Circuit breaker: if mythos_step queue depth is still pathological, nuke it.
    const { count: mythosQueued } = await supa.from("scan_jobs")
      .select("id", { count: "exact", head: true })
      .eq("status", "queued").eq("job_type", "mythos_step");
    if ((mythosQueued ?? 0) > 1000) {
      await supa.from("scan_jobs").delete()
        .eq("status", "queued").eq("job_type", "mythos_step");
      console.log(`circuit_breaker tripped: deleted ${mythosQueued} mythos_step jobs`);
    }

    const limit = 5;
    const { data: jobs } = await supa.from("scan_jobs")
      .select("*").eq("status", "queued").lte("next_run_at", new Date().toISOString())
      .order("priority", { ascending: false }).order("created_at").limit(limit);

    if (!jobs || jobs.length === 0) {
      return new Response(JSON.stringify({ picked: 0, message: "no queued jobs" }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // Targets recently flagged as AI-exhausted → skip AI-heavy job types for 10min.
    const aiHeavy = new Set(["mythos_step", "debate", "variant_test", "ollama_mutate", "patch_validate"]);
    const recentExhausted = new Set<string>();
    const targetIds = [...new Set(jobs.map((j: any) => j.target_id).filter(Boolean))];
    if (targetIds.length) {
      const since = new Date(Date.now() - 10 * 60_000).toISOString();
      const { data: sentinels } = await supa.from("scan_logs")
        .select("target_id, metadata").in("target_id", targetIds)
        .eq("log_type", "error").gte("created_at", since);
      for (const s of sentinels || []) {
        if ((s.metadata as any)?.kind === "ai_credits_exhausted") recentExhausted.add(s.target_id);
      }
    }

    const results: any[] = [];
    for (const job of jobs) {
      if (recentExhausted.has(job.target_id) && aiHeavy.has(job.job_type)) {
        await supa.from("scan_jobs").update({
          status: "queued",
          error_message: "deferred: AI credits exhausted",
          next_run_at: new Date(Date.now() + 10 * 60_000).toISOString(),
        }).eq("id", job.id);
        results.push({ id: job.id, type: job.job_type, deferred: true });
        continue;
      }

      await supa.from("scan_jobs").update({
        status: "running", started_at: new Date().toISOString(), attempts: job.attempts + 1,
      }).eq("id", job.id);

      const out = await runJob(job);

      // Hard-stop on AI credit exhaustion — write sentinel so other jobs/UI react.
      if (detectCreditExhaustion(out.result, out.error)) {
        await supa.from("scan_logs").insert({
          target_id: job.target_id, log_type: "error",
          message: `🪫 AI credits exhausted during ${job.job_type} — scan paused.`,
          metadata: { kind: "ai_credits_exhausted", phase: job.job_type, job_id: job.id, until: new Date(Date.now() + 10 * 60_000).toISOString() },
        });
      }

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
        await supa.from("scan_logs").insert({
          target_id: job.target_id, log_type: "error",
          message: `❌ ${job.job_type} failed: ${String(out.error).slice(0, 200)}`,
          metadata: { kind: "job_failure", job_id: job.id, attempts: job.attempts + 1, final: isFinal },
        }).catch(() => {});
      }
      results.push({ id: job.id, type: job.job_type, ok: out.ok, error: out.error });
    }

    return new Response(JSON.stringify({ picked: jobs.length, results }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: e instanceof Error ? e.message : "err" }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});

