// Mythos Orchestrator — single-phase executor for long-horizon runs.
// Reads `mythos_runs.current_phase`, executes ONE phase (≤45s), then
// either (a) advances current_phase + enqueues itself via scan_jobs, or
// (b) marks the run complete. Survives the 50s edge limit by being resumable.
//
// Phases: init → sast → iter-N-chain → iter-N-variant → iter-N-debate → iter-N+1-chain → … → patch → done
// Always returns 200 OK.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { areCreditsRecentlyExhausted } from "../_shared/ai-credits.ts";

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
  // Guard 1: run must still be 'running' — otherwise we're spawning orphans
  const { data: run } = await db.from("mythos_runs").select("status").eq("id", runId).maybeSingle();
  if (!run || run.status !== "running") {
    console.log(`enqueueNext skipped: run ${runId} status=${run?.status ?? "missing"}`);
    return;
  }
  // Guard 2: dedupe — don't queue if an identical step is already queued OR running
  // FIX: previously only checked "queued" — jobs already "running" bypassed the guard
  // causing the kill-chain infinite loop (multiple concurrent synthesis jobs)
  const { count: queuedCount } = await db.from("scan_jobs")
    .select("id", { count: "exact", head: true })
    .in("status", ["queued", "running"])
    .eq("job_type", "mythos_step")
    .filter("payload->>runId", "eq", runId)
    .filter("payload->>nextPhase", "eq", nextPhase);
  if ((queuedCount ?? 0) > 0) {
    console.log(`enqueueNext skipped: dup queued/running for ${runId}/${nextPhase}`);
    return;
  }
  const { enqueueJob } = await import("../_shared/enqueue.ts");
  await enqueueJob(db, {
    target_id: targetId,
    job_type: "mythos_step",
    payload: { runId, nextPhase, ...payload },
    priority: 7,
    dedupWindowMs: 10 * 60_000,
    dedupExtraKey: `${runId}|${nextPhase}`,
  });
  // No self-fire — pg_cron + scan-job-worker will pick it up. Self-fire caused cascade fanout.
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
    return { done: false, nextPhase: "advanced-modules" };
  }

  if (phase === "advanced-modules") {
    await log(`🧪 Advanced attack modules + per-asset matrix fuzz + form-attacker + juicy recon`);
    const mods = [
      "business-logic-fuzzer", "auth-confusion-suite", "prototype-pollution-gadgets",
      "ai-surface-attacker", "differential-oracle", "symbolic-param-explorer", "desync-smuggling-v2",
      "matrix-fuzzer", "form-attacker", "recon-juicy",
      // NEW: LLM attack surface + NVD-matched CVE testing
      "llm-attack-suite", "live-cve-runner",
    ];
    const settled = await Promise.allSettled(mods.map(m => call(m, { targetId }, 42000)));
    const summary: Record<string, any> = {};
    settled.forEach((s, i) => { summary[mods[i]] = s.status === "fulfilled" ? (s.value.data ?? s.value) : { error: true }; });
    await log(`Advanced modules done (incl. matrix-fuzzer, form-attacker, recon-juicy)`, summary);
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
    await log(`🥷 Debate phase (parallel fan-out, max 6) — iter ${meta.iter}`);
    const { data: eps } = await db.from("discovered_endpoints").select("url,parameters").eq("target_id", targetId).limit(50);
    const COMMON = ["q", "id", "search", "url", "redirect", "page", "file", "user", "token", "next"];

    // Gap 1 fix: rotate candidate window by iteration so debates 2/3/4 see DIFFERENT pairs.
    const iterOffset = ((meta.iter || 1) - 1) * 5;
    // Build candidate list (endpoint × param), then slice the iteration window.
    const allCandidates: Array<{ url: string; param: string; value: string }> = [];
    for (const ep of eps || []) {
      let params = (ep.parameters as Record<string, string>) || {};
      if (Object.keys(params).length === 0) {
        try { params = Object.fromEntries(new URL(ep.url).searchParams); } catch {}
      }
      if (Object.keys(params).length === 0) params = Object.fromEntries(COMMON.map(p => [p, "test"]));
      for (const pk of Object.keys(params).slice(0, 6)) {
        allCandidates.push({ url: ep.url, param: pk, value: params[pk] });
      }
    }
    const candidates = allCandidates.slice(iterOffset, iterOffset + 20).length >= 5
      ? allCandidates.slice(iterOffset, iterOffset + 20)
      : allCandidates.slice(0, 20); // fall back to head if exhausted

    const settled = await Promise.allSettled(
      candidates.map(c =>
        call("mythos-debate", { targetId, runId, endpointUrl: c.url, paramName: c.param, paramValue: c.value, vulnClassHint: "auto", iteration: meta.iter }, 28000)
      ),
    );
    let debates = 0, tp = 0, fp = 0, incon = 0;
    for (const s of settled) {
      if (s.status === "fulfilled" && s.value.ok) {
        debates++;
        const v = s.value.data?.fpVerdict;
        if (v === "true_positive") tp++;
        else if (v === "false_positive") fp++;
        else incon++;
      }
    }
    await log(`Debates: ${debates}/${candidates.length} run in parallel, ${tp} TP, ${fp} FP, ${incon} inconclusive`, { debates, tp, fp, incon, parallel: candidates.length, iterOffset });
    // Browser-exploit pass on top XSS findings
    const { data: xssFindings } = await db.from("vulnerability_findings")
      .select("id").eq("target_id", targetId).ilike("finding_type", "%xss%").lt("proof_tier", "exploited").limit(10);
    for (const xf of xssFindings || []) {
      await call("browser-exploit", { findingId: xf.id }, 35000);
    }

    // Auto-execute high-CVSS chains (combined_cvss >= 7) once per iteration
    const { data: hotChains } = await db.from("mythos_chains")
      .select("id,chain_name,combined_cvss").eq("target_id", targetId).eq("execution_status", "proposed")
      .gte("combined_cvss", 7).limit(6);
    for (const c of hotChains || []) {
      await log(`⛓️  Auto-executing chain '${c.chain_name}' (cvss=${c.combined_cvss})`, { chainId: c.id });
      await call("exploit-chain-runner", { chainId: c.id, targetId }, 40000);
    }

    // Gap 12 assertion: warn if no exploit_runs in this iteration window.
    try {
      const since = new Date(Date.now() - 5 * 60_000).toISOString();
      const { count } = await db.from("exploit_runs").select("id", { count: "exact", head: true }).eq("target_id", targetId).gte("created_at", since);
      if ((count ?? 0) === 0) {
        await log(`⚠️ No exploit_runs in last 5min — pipeline may be dropping signals before exploit engine (iter ${meta.iter})`, { kind: "exploit_runs_missing", iter: meta.iter });
      }
    } catch { /* ignore */ }

    // Decide next: more iterations or synthesize kill-chains then patch?
    if (meta.iter! < run.max_iterations) {
      if (debates === 0 && tp === 0 && incon === 0 && meta.iter! >= 2) {
        return { done: false, nextPhase: "kill-chain-synthesis", results: { early_stop: true } };
      }
      return { done: false, nextPhase: `iter-${meta.iter! + 1}-chain` };
    }
    return { done: false, nextPhase: "kill-chain-synthesis" };

  }

  if (phase === "kill-chain-synthesis") {
    await log(`⛓️ Synthesizing Kill-Chain Attack Graph`);
    const r = await call("kill-chain-graph", { targetId }, 45000);
    await log(`Kill-Chain Graph: ${r.data?.nodes || 0} nodes, ${r.data?.edges || 0} edges, ${r.data?.chains || 0} chains`, r.data);
    return { done: false, nextPhase: "patch" };
  }

  if (phase === "patch") {
    await log(`🩹 Auto-patching top findings`);
    const { data: top } = await db.from("vulnerability_findings")
      .select("id").eq("target_id", targetId).order("cvss_score", { ascending: false, nullsFirst: false }).limit(8);
    for (const f of top || []) await call("mythos-patcher", { findingId: f.id, targetId }, 30000);
    return { done: true };
  }

  await log(`❌ Unknown phase '${phase}' — refusing to silently complete; marking run failed`, { unknown_phase: phase });
  await db.from("mythos_runs").update({
    status: "failed", completed_at: new Date().toISOString(),
  }).eq("id", runId);
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
      const { targetId, maxIterations = 8, repoUrl, triggerType = "manual" } = body;
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

    // 🪫 If a recent credit-exhaustion sentinel exists for this target, pause cleanly
    // instead of fanning out 6×N more LLM-burning debates.
    if (await areCreditsRecentlyExhausted(db, run.target_id, 10)) {
      await db.from("mythos_runs").update({
        status: "paused", current_phase: phase,
        thought_log: (run.thought_log || []).concat([{
          ts: new Date().toISOString(), phase, msg: "Paused: AI credits exhausted. Resume after topping up.",
        }]),
      }).eq("id", runId);
      // Throttle the user-visible "paused" log to once per hour so we don't
      // spam scan_logs 30× while the arbiter/worker keep polling.
      const sincePauseLog = new Date(Date.now() - 60 * 60_000).toISOString();
      const { data: recentPause } = await db.from("scan_logs").select("id")
        .eq("target_id", run.target_id)
        .like("message", "%Mythos run paused%")
        .gte("created_at", sincePauseLog).limit(1);
      if (!recentPause || recentPause.length === 0) {
        await db.from("scan_logs").insert({
          target_id: run.target_id, log_type: "error",
          message: `⏸️ Mythos run paused — AI credits exhausted. Add credits in Workspace → Usage and re-trigger.`,
          metadata: { runId, phase, kind: "ai_credits_exhausted" },
        } as any);
      }
      return ok({ ok: true, runId, status: "paused", reason: "ai_credits_exhausted" });
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
