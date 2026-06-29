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
  chain_exploit: "chain-exploit",
  waf_evasion: "waf-evasion-engine",
  graphql: "graphql-attack",
  jwt_attack: "auth-confusion-suite",
  nvd_sync: "nvd-intel-sync",
  openapi_import: "openapi-importer",
  juicy: "recon-juicy",
  advanced_detect: "advanced-detectors",
  // Gap wiring (1-10)
  differential: "differential-oracle",  // Gap #5
  js_deep: "js-deep-expand",            // Gap #7
  ssrf_deep: "ssrf-deep",               // Gap #8
  cve_exploit: "cve-to-exploit",        // Gap #9
  report_rewrite: "report-rewrite",     // Gap #10
  matrix_fuzz: "matrix-fuzzer",         // Gap #1 (auth-aware fuzz)
  form_attack: "form-attacker",
  // Phase arbiter + AI strategist + watchdog
  hypothesis_test: "hypothesis-test-runner",
  ai_strategist: "ai-strategist",
  exploit_watchdog: "exploit-watchdog",
  phase_arbiter: "phase-arbiter",
};


// Per-type dispatch timeout (ms). Long-running types return 202 quickly via
// EdgeRuntime.waitUntil OR keep running on the backend — we only need to wait
// for the HTTP ack, not the full work, otherwise the worker's AbortSignal
// kills the connection at 45s and marks the job failed even though the
// function is still doing useful work in the background.
const ACK_TIMEOUT_MS: Record<string, number> = {
  recon: 15000,
  fuzz: 15000,
  waf_evasion: 12000,
  chain_exploit: 15000,
  llm_attack: 15000,
  advanced_detect: 15000,
  juicy: 15000,
  exploit: 20000,
  variant_test: 15000,
  browser: 20000,
  browser_exploit: 20000,
  chain: 20000,
  chain_exec: 20000,
  graphql: 15000,
  jwt_attack: 15000,
  openapi_import: 15000,
  nvd_sync: 20000,
  mythos_step: 15000,
  // Gap wiring
  differential: 15000,
  js_deep: 15000,
  ssrf_deep: 20000,
  cve_exploit: 12000,
  report_rewrite: 20000,
  matrix_fuzz: 20000,
  form_attack: 15000,
  hypothesis_test: 15000,
  ai_strategist: 10000,
  exploit_watchdog: 10000,
  phase_arbiter: 8000,
};

const DEFAULT_TIMEOUT_MS = 45000;

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
  const timeoutMs = ACK_TIMEOUT_MS[job.job_type] ?? DEFAULT_TIMEOUT_MS;
  try {
    const modePayload = job.job_type === "ollama_mutate" ? { mode: "ai" } : job.job_type === "local_tool" ? { mode: "tool" } : {};
    const r = await fetch(`${FN_BASE}/${route}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${SERVICE_KEY}` },
      body: JSON.stringify({ targetId: job.target_id, ...modePayload, ...job.payload }),
      signal: AbortSignal.timeout(timeoutMs),
    });
    // For known long-running types, ANY 2xx is success — don't drain body.
    const isAckType = job.job_type in ACK_TIMEOUT_MS;
    if (r.ok) {
      if (isAckType) {
        // best-effort body read but don't block long; ignore parse errors
        const text = await Promise.race([
          r.text(),
          new Promise<string>((resolve) => setTimeout(() => resolve("{}"), 2000)),
        ]).catch(() => "{}");
        let body: any = text; try { body = JSON.parse(text); } catch { /* ignore */ }
        return { ok: true, result: { acked: true, status: r.status, body } };
      }
      const text = await r.text();
      let body: any = text; try { body = JSON.parse(text); } catch { /* ignore */ }
      return { ok: true, result: body };
    }
    const text = await r.text().catch(() => "");
    let body: any = text; try { body = JSON.parse(text); } catch { /* ignore */ }
    return { ok: false, error: `HTTP ${r.status}`, result: body };
  } catch (e) {
    const msg = e instanceof Error ? e.message : "err";
    // Treat ack-timeout on long-running types as soft-success: the function
    // likely accepted the work and is running in background; the next worker
    // tick won't re-dispatch because we mark it done.
    if (/timed out/i.test(msg) && (job.job_type in ACK_TIMEOUT_MS)) {
      return { ok: true, result: { acked: false, soft_success: true, note: "dispatch ack timed out — function continues in background" } };
    }
    return { ok: false, error: msg };
  }
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

        // ── Post-phase fan-out: ensure the chain keeps moving even if a
        // module forgets to enqueue the next stage. Idempotent: scan_jobs
        // unique index + per-type "running" check prevents duplicates.
        if (job.job_type === "recon") {
          try {
            const { data: tgt } = await supa.from("target_workspaces")
              .select("api_schema_url").eq("id", job.target_id).maybeSingle();
            const nowIso = new Date().toISOString();
            const followups: any[] = [
              { target_id: job.target_id, job_type: "juicy",           status: "queued", priority: 7, payload: {}, next_run_at: nowIso },
              { target_id: job.target_id, job_type: "advanced_detect", status: "queued", priority: 7, payload: {}, next_run_at: nowIso },
              { target_id: job.target_id, job_type: "fuzz",            status: "queued", priority: 6, payload: {}, next_run_at: nowIso },
              { target_id: job.target_id, job_type: "llm_attack",      status: "queued", priority: 6, payload: {}, next_run_at: nowIso },
              { target_id: job.target_id, job_type: "chain",           status: "queued", priority: 5, payload: {}, next_run_at: nowIso },
              { target_id: job.target_id, job_type: "nvd_sync",        status: "queued", priority: 4, payload: { action: "relevance-check", targetId: job.target_id }, next_run_at: nowIso },
              { target_id: job.target_id, job_type: "graphql",         status: "queued", priority: 6, payload: {}, next_run_at: nowIso },
              { target_id: job.target_id, job_type: "jwt_attack",      status: "queued", priority: 6, payload: {}, next_run_at: nowIso },
              { target_id: job.target_id, job_type: "waf_evasion",     status: "queued", priority: 9, payload: {}, next_run_at: nowIso },
              { target_id: job.target_id, job_type: "chain_exploit",   status: "queued", priority: 5, payload: {}, next_run_at: new Date(Date.now() + 120_000).toISOString() },
              // Gap wiring fan-out (1-10):
              { target_id: job.target_id, job_type: "js_deep",         status: "queued", priority: 8, payload: {}, next_run_at: nowIso },                                       // Gap #7
              { target_id: job.target_id, job_type: "matrix_fuzz",     status: "queued", priority: 7, payload: {}, next_run_at: new Date(Date.now() + 30_000).toISOString() },   // Gap #1 (auth-aware)
              { target_id: job.target_id, job_type: "form_attack",     status: "queued", priority: 7, payload: {}, next_run_at: new Date(Date.now() + 45_000).toISOString() },
              { target_id: job.target_id, job_type: "differential",    status: "queued", priority: 6, payload: {}, next_run_at: new Date(Date.now() + 60_000).toISOString() },   // Gap #5
              { target_id: job.target_id, job_type: "ssrf_deep",       status: "queued", priority: 6, payload: {}, next_run_at: new Date(Date.now() + 60_000).toISOString() },   // Gap #8
              { target_id: job.target_id, job_type: "cve_exploit",     status: "queued", priority: 7, payload: {}, next_run_at: new Date(Date.now() + 30_000).toISOString() },   // Gap #9
              { target_id: job.target_id, job_type: "report_rewrite",  status: "queued", priority: 2, payload: {}, next_run_at: new Date(Date.now() + 300_000).toISOString() },  // Gap #10 (runs late)
            ];

            if (tgt?.api_schema_url) {
              followups.push({ target_id: job.target_id, job_type: "openapi_import", status: "queued", priority: 8, payload: { autoAttack: true }, next_run_at: nowIso });
            }
            await supa.from("scan_jobs").insert(followups);
            await supa.from("scan_logs").insert({
              target_id: job.target_id, log_type: "info",
              message: `🔗 recon done → fanned out ${followups.length} follow-up phases`,
              metadata: { kind: "phase_fanout", types: followups.map((f: any) => f.job_type) },
            });
          } catch (e) { /* dedup index may reject duplicates — fine */ }
        }
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

    // Ping the phase arbiter for active targets so the pipeline keeps moving.
    const activeTargets = [...new Set(jobs.map((j: any) => j.target_id).filter(Boolean))];
    for (const t of activeTargets) {
      fetch(`${FN_BASE}/phase-arbiter`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${SERVICE_KEY}` },
        body: JSON.stringify({ targetId: t }),
        signal: AbortSignal.timeout(3000),
      }).catch(() => {});

    return new Response(JSON.stringify({ picked: jobs.length, results }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: e instanceof Error ? e.message : "err" }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});

