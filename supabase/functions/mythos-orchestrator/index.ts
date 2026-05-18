// Mythos Orchestrator — single-phase executor for long-horizon runs.
// Reads `mythos_runs.current_phase`, executes ONE phase (≤45s), then
// either (a) advances current_phase + enqueues itself via scan_jobs, or
// (b) marks the run complete. Survives the 50s edge limit by being resumable.
//
// Phases: init → sast → iter-N-chain → iter-N-variant → iter-N-debate → iter-N+1-chain → … → patch → done
// Always returns 200 OK.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

async function call(fn: string, body: any, timeoutMs = 40000) {
  try {
    const r = await fetch(`${SUPABASE_URL}/functions/v1/${fn}`, {
      method: "POST",
      headers: { Authorization: `Bearer ${SERVICE_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
    const t = await r.text();
    try { return { ok: r.ok, data: JSON.parse(t) }; } catch { return { ok: r.ok, data: { raw: t } }; }
  } catch (e) { return { ok: false, data: { error: e instanceof Error ? e.message : "err" } }; }
}

function parsePhase(p: string): { kind: string; iter?: number; sub?: string } {
  // "iter-3-chain" → { kind: "iter", iter: 3, sub: "chain" }
  const m = /^iter-(\d+)-(\w+)$/.exec(p);
  if (m) return { kind: "iter", iter: parseInt(m[1]), sub: m[2] };
  return { kind: p };
}

async function enqueueNext(db: any, runId: string, targetId: string, nextPhase: string, payload: any = {}) {
  await db.from("scan_jobs").insert({
    target_id: targetId,
    job_type: "mythos_step",
    payload: { runId, nextPhase, ...payload },
    status: "queued",
    priority: 7,
  });
}

async function executePhase(db: any, run: any, phase: string, payload: any): Promise<{ done: boolean; nextPhase?: string; results?: any }> {
  const targetId = run.target_id;
  const runId = run.id;
  const meta = parsePhase(phase);

  const log = async (msg: string, extra: any = {}) => {
    const newLog = [...(run.thought_log || []), { ts: new Date().toISOString(), phase, msg, ...extra }].slice(-200);
    await db.from("mythos_runs").update({ thought_log: newLog, current_phase: phase, updated_at: new Date().toISOString() }).eq("id", runId);
    await db.from("scan_logs").insert({ target_id: targetId, log_type: "info", message: `🧠 Mythos[${phase}]: ${msg}`, metadata: { run_id: runId, ...extra } });
  };

  // ── INIT → SAST or first iteration ──
  if (phase === "init") {
    await log("Run resumed — starting orchestration");
    const repoUrl = payload.repoUrl || run.payload?.repoUrl;
    return { done: false, nextPhase: repoUrl ? "sast" : "asset-scan", results: { repoUrl } };
  }

  if (phase === "sast") {
    const repoUrl = payload.repoUrl;
    await log(`📚 SAST ingest from ${repoUrl}`);
    if (repoUrl) {
      const r = await call("mythos-codebase-ingest", { targetId, repoUrl }, 45000);
      await log(`SAST: ${r.data?.findingsCount || 0} findings in ${r.data?.fileCount || 0} files`, { sast: r.data });
    }
    return { done: false, nextPhase: "asset-scan" };
  }

  if (phase === "asset-scan") {
    await log(`🔑 Deep asset scan — secrets / source bugs / debug paths / blind SSRF`);
    const r = await call("deep-asset-scan", { targetId }, 50000);
    await log(`Asset scan: ${r.data?.secrets || 0} secrets, ${r.data?.codeBugs || 0} code bugs, ${r.data?.debugPaths || 0} debug paths, ${r.data?.ssrfInjections || 0} SSRF probes`, { asset: r.data });
    return { done: false, nextPhase: "template-runner" };
  }

  if (phase === "template-runner") {
    await log(`🧪 Nuclei-style template runner (OWASP Top 10 + CVEs, WAF-aware)`);
    const r = await call("template-runner", { targetId, scanRunId: runId }, 48000);
    await log(`Templates: ${r.data?.findings || 0} findings, WAF=${r.data?.waf?.vendor || "none"}`, { template: r.data });
    return { done: false, nextPhase: "iter-1-chain" };
  }

  if (meta.kind === "iter" && meta.sub === "chain") {
    await db.from("mythos_runs").update({ iteration: meta.iter }).eq("id", runId);
    await log(`🔗 Iteration ${meta.iter}/${run.max_iterations} — chainer`);
    const r = await call("mythos-chainer", { targetId, runId }, 40000);
    return { done: false, nextPhase: `iter-${meta.iter}-variant`, results: { chainsCount: r.data?.chainsCount || 0 } };
  }

  if (meta.kind === "iter" && meta.sub === "variant") {
    await log(`🌀 Variant generator`);
    const r = await call("mythos-variant-gen", { targetId, runId }, 40000);
    return { done: false, nextPhase: `iter-${meta.iter}-debate`, results: { variants: r.data?.variantsCount || 0 } };
  }

  if (meta.kind === "iter" && meta.sub === "debate") {
    await log(`🥷 Debate phase (parallel fan-out, max 6)`);
    const { data: eps } = await db.from("discovered_endpoints").select("url,parameters").eq("target_id", targetId).limit(15);
    const COMMON = ["q", "id", "search", "url", "redirect"];

    // Build the candidate list (endpoint × param) up-front, then fan out in parallel.
    const candidates: Array<{ url: string; param: string; value: string }> = [];
    for (const ep of eps || []) {
      let params = (ep.parameters as Record<string, string>) || {};
      if (Object.keys(params).length === 0) {
        try { params = Object.fromEntries(new URL(ep.url).searchParams); } catch {}
      }
      if (Object.keys(params).length === 0) params = Object.fromEntries(COMMON.map(p => [p, "test"]));
      for (const pk of Object.keys(params).slice(0, 2)) {
        candidates.push({ url: ep.url, param: pk, value: params[pk] });
        if (candidates.length >= 6) break;
      }
      if (candidates.length >= 6) break;
    }

    const settled = await Promise.allSettled(
      candidates.map(c =>
        call("mythos-debate", { targetId, runId, endpointUrl: c.url, paramName: c.param, paramValue: c.value, vulnClassHint: "auto" }, 28000)
      ),
    );
    let debates = 0, tp = 0, fp = 0;
    for (const s of settled) {
      if (s.status === "fulfilled" && s.value.ok) {
        debates++;
        if (s.value.data?.fpVerdict === "true_positive") tp++;
        if (s.value.data?.fpVerdict === "false_positive") fp++;
      }
    }
    await log(`Debates: ${debates}/${candidates.length} run in parallel, ${tp} TP, ${fp} FP`, { debates, tp, fp, parallel: candidates.length });
    // Browser-exploit pass on top XSS findings
    const { data: xssFindings } = await db.from("vulnerability_findings")
      .select("id").eq("target_id", targetId).ilike("finding_type", "%xss%").lt("proof_tier", "exploited").limit(3);
    for (const xf of xssFindings || []) {
      await call("browser-exploit", { findingId: xf.id }, 35000);
    }

    // Decide next: more iterations or move to patch?
    if (meta.iter! < run.max_iterations) {
      // Stop early if no progress and we've done at least 2 iters
      if (debates === 0 && tp === 0 && meta.iter! >= 2) {
        return { done: false, nextPhase: "patch", results: { early_stop: true } };
      }
      return { done: false, nextPhase: `iter-${meta.iter! + 1}-chain` };
    }
    return { done: false, nextPhase: "patch" };
  }

  if (phase === "patch") {
    await log(`🩹 Auto-patching top findings`);
    const { data: top } = await db.from("vulnerability_findings")
      .select("id").eq("target_id", targetId).order("cvss_score", { ascending: false, nullsFirst: false }).limit(3);
    for (const f of top || []) await call("mythos-patcher", { findingId: f.id, targetId }, 30000);
    return { done: true };
  }

  await log(`Unknown phase '${phase}' — completing run`);
  return { done: true };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  const ok = (b: Record<string, unknown>) =>
    new Response(JSON.stringify(b), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });

  try {
    const body = await req.json().catch(() => ({}));
    const db = createClient(SUPABASE_URL, SERVICE_KEY, { auth: { persistSession: false } });

    let runId = body.runId;
    let phase = body.nextPhase || body.phase || "init";

    // Bootstrap a new run if none provided
    if (!runId) {
      const { targetId, maxIterations = 4, repoUrl, triggerType = "manual" } = body;
      if (!targetId) return ok({ ok: false, error: "targetId required" });
      const { data: run, error } = await db.from("mythos_runs").insert({
        target_id: targetId, trigger_type: triggerType, max_iterations: maxIterations,
        status: "running", started_at: new Date().toISOString(), current_phase: "init",
        thought_log: [{ ts: new Date().toISOString(), phase: "boot", msg: "Long-horizon run created" }],
      }).select().single();
      if (error) return ok({ ok: false, error: error.message });
      runId = run.id;
      // Immediately enqueue the first step so we don't block
      await enqueueNext(db, runId, targetId, "init", { repoUrl });
      return ok({ ok: true, runId, queued: "init", message: "Run bootstrapped, first step enqueued" });
    }

    // Resume an existing run for one phase
    const { data: run } = await db.from("mythos_runs").select("*").eq("id", runId).maybeSingle();
    if (!run) return ok({ ok: false, error: "run not found" });
    if (run.status === "complete" || run.status === "failed") {
      return ok({ ok: true, message: `run already ${run.status}` });
    }

    const out = await executePhase(db, run, phase, body);

    if (out.done) {
      await db.from("mythos_runs").update({
        status: "complete", completed_at: new Date().toISOString(), current_phase: "done",
      }).eq("id", runId);
      await db.from("scan_logs").insert({
        target_id: run.target_id, log_type: "result",
        message: `🏁 Mythos long-horizon run COMPLETE`, metadata: { runId },
      } as any);
      return ok({ ok: true, runId, status: "complete" });
    }

    // Enqueue the next phase via scan_jobs (worker will pick it up)
    if (out.nextPhase) {
      await enqueueNext(db, runId, run.target_id, out.nextPhase, out.results || {});
    }

    return ok({ ok: true, runId, ranPhase: phase, queuedNext: out.nextPhase, results: out.results });
  } catch (e) {
    return ok({ ok: false, error: e instanceof Error ? e.message : String(e) });
  }
});
