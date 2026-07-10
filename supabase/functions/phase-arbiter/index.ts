// phase-arbiter — runs every minute via pg_cron and after every job completes.
// Detects stalled phases, force-advances the pipeline, seeds the OWASP checklist,
// and triggers the AI strategist after owasp_matrix.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

const SUPA = Deno.env.get("SUPABASE_URL")!;
const SVC = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const FN_BASE = `${SUPA}/functions/v1`;

const PHASES = ["recon", "discovery", "owasp_matrix", "deep_modules", "exploit", "chain", "report"] as const;
const PHASE_ORDER: Record<string, number> = {
  recon: 1, discovery: 2, owasp_matrix: 3, deep_modules: 4, exploit: 5, chain: 6, report: 7,
};
const STALL_MS = 5 * 60_000;

// Map phase → job types that fulfill it. Prerequisites are enforced by
// PHASE_ORDER; a phase cannot begin until every earlier phase is complete OR
// failed (never pending/running).
const PHASE_JOBS: Record<string, { type: string; priority: number; payload?: any }[]> = {
  discovery: [
    { type: "subdomain_enum", priority: 9 },
    { type: "juicy", priority: 8 },
    { type: "js_deep", priority: 7 },
    { type: "vuln_scan", priority: 6 },
  ],
  owasp_matrix: [
    { type: "fuzz", priority: 7 },
    { type: "matrix_fuzz", priority: 7 },
    { type: "advanced_detect", priority: 7 },
    { type: "form_attack", priority: 6 },
    { type: "graphql", priority: 6 },
    { type: "jwt_attack", priority: 6 },
    { type: "ssrf_deep", priority: 6 },
    { type: "differential", priority: 6 },
    { type: "auth_replay", priority: 6 },
    { type: "cve", priority: 5 },
  ],
  deep_modules: [
    { type: "llm_attack", priority: 6 },
    { type: "waf_evasion", priority: 8 },
    { type: "cve_exploit", priority: 7 },
    { type: "ai_strategist", priority: 7 },
    { type: "nvd_sync", priority: 4 },
  ],
  exploit: [{ type: "exploit_watchdog", priority: 8 }],
  chain: [
    { type: "chain", priority: 5 },
    { type: "chain_exploit", priority: 5 },
  ],
  report: [{ type: "report_rewrite", priority: 2 }],
};

// Which job_types must have succeeded (status='done') before a phase can be
// considered fully complete. Used by the completion gate below.
const EXPECTED_MODULES: Record<string, string[]> = Object.fromEntries(
  Object.entries(PHASE_JOBS).map(([p, jobs]) => [p, jobs.map((j) => j.type)]),
);

async function callFn(name: string, body: any) {
  try {
    await fetch(`${FN_BASE}/${name}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${SVC}` },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(6000),
    }).catch(() => {});
  } catch {
    /* ignore */
  }
}

async function enqueue(db: any, targetId: string, jobs: { type: string; priority: number; payload?: any }[]) {
  const now = new Date().toISOString();
  // Filter out: already running, or queued + recent
  const types = jobs.map((j) => j.type);
  const { data: existing } = await db
    .from("scan_jobs")
    .select("job_type,status")
    .eq("target_id", targetId)
    .in("job_type", types)
    .in("status", ["queued", "running"]);
  const busy = new Set((existing || []).map((e: any) => e.job_type));
  const rows = jobs
    .filter((j) => !busy.has(j.type))
    .map((j) => ({
      target_id: targetId,
      job_type: j.type,
      status: "queued",
      priority: j.priority,
      payload: j.payload ?? {},
      next_run_at: now,
    }));
  if (rows.length)
    await db
      .from("scan_jobs")
      .insert(rows)
      .then(
        () => {},
        () => {},
      );
  return rows.length;
}

async function loadJobHistory(db: any, targetId: string) {
  const { data } = await db
    .from("scan_jobs")
    .select("job_type,status,created_at,completed_at")
    .eq("target_id", targetId)
    .order("created_at", { ascending: false })
    .limit(500);
  const latest = new Map<string, any>();
  for (const j of data || []) if (!latest.has(j.job_type)) latest.set(j.job_type, j);
  return latest;
}

async function arbitrateTarget(db: any, targetId: string) {
  try { await db.rpc("seed_owasp_checklist", { _target_id: targetId }); } catch { /* ignore */ }

  const { data: phaseRows } = await db
    .from("scan_phase_state")
    .select("phase,status,last_heartbeat,checks_attempted,findings_count,metadata")
    .eq("target_id", targetId);

  const phaseMap = new Map((phaseRows || []).map((p: any) => [p.phase, p]));
  const jobLatest = await loadJobHistory(db, targetId);
  const advanced: string[] = [];

  // Iterate strictly in phase_order so a later phase can never leap ahead.
  const orderedPhases = [...PHASES].sort((a, b) => PHASE_ORDER[a] - PHASE_ORDER[b]);

  for (const phase of orderedPhases) {
    const p: any = phaseMap.get(phase);
    const expected = EXPECTED_MODULES[phase] || [];

    // Stalled running → mark failed and fall through so the loop can advance.
    if (p?.status === "running") {
      const age = Date.now() - new Date(p.last_heartbeat).getTime();
      if (age > STALL_MS) {
        await db.from("scan_phase_state").update({
          status: "failed",
          completed_at: new Date().toISOString(),
          metadata: { ...(p.metadata || {}), stalled: true, stalled_after_ms: age },
        }).eq("target_id", targetId).eq("phase", phase);
      } else {
        // Running: gate — check whether all expected modules are actually
        // "done"; if so, promote to complete instead of waiting for STALL_MS.
        if (expected.length > 0) {
          const allDone = expected.every((m) => jobLatest.get(m)?.status === "done");
          if (allDone) {
            await db.from("scan_phase_state").upsert({
              target_id: targetId, phase,
              phase_order: PHASE_ORDER[phase],
              expected_modules: expected,
              status: "complete",
              completed_at: new Date().toISOString(),
              last_heartbeat: new Date().toISOString(),
            }, { onConflict: "target_id,phase" });
            advanced.push(`${phase}=complete`);
            continue;
          }
        }
        return advanced; // still alive, wait
      }
    }

    // Pending or failed → check prerequisites, then start
    if (!p || p.status === "pending" || p.status === "failed") {
      if (phase === "recon") continue; // recon triggered externally

      // Prerequisite gate: every earlier phase must be complete OR failed
      // (never pending/running). This is what enforces strict VAPT ordering.
      const prereqBlocked = orderedPhases
        .filter((ph) => PHASE_ORDER[ph] < PHASE_ORDER[phase])
        .some((ph) => {
          const pp: any = phaseMap.get(ph);
          if (!pp) return ph !== "recon"; // treat missing as blocking (recon starts things)
          return pp.status === "pending" || pp.status === "running";
        });
      if (prereqBlocked) return advanced;

      const jobs = PHASE_JOBS[phase];
      if (jobs?.length) {
        await db.from("scan_phase_state").upsert({
          target_id: targetId, phase,
          phase_order: PHASE_ORDER[phase],
          expected_modules: expected,
          status: "running",
          started_at: new Date().toISOString(),
          last_heartbeat: new Date().toISOString(),
          metadata: { ...(p?.metadata || {}), prereq_ok: true, started_by: "phase-arbiter" },
        }, { onConflict: "target_id,phase" });

        const direct = jobs.filter((j) => j.type === "ai_strategist" || j.type === "exploit_watchdog");
        const queued = jobs.filter((j) => j.type !== "ai_strategist" && j.type !== "exploit_watchdog");
        for (const d of direct)
          await callFn(d.type === "ai_strategist" ? "ai-strategist" : "exploit-watchdog", { targetId });
        const n = await enqueue(db, targetId, queued);
        advanced.push(`${phase}+${n}`);
      } else {
        await db.from("scan_phase_state").upsert({
          target_id: targetId, phase,
          phase_order: PHASE_ORDER[phase],
          expected_modules: expected,
          status: "complete",
          completed_at: new Date().toISOString(),
          last_heartbeat: new Date().toISOString(),
        }, { onConflict: "target_id,phase" });
      }
      return advanced;
    }
    // complete → advance to next phase in order
  }
  await db.rpc("enqueue_missing_owasp_modules", { _target_id: targetId, _force: false }).then(() => {}, () => {});
  return advanced;
}

async function detectActiveTargets(db: any): Promise<string[]> {
  // Targets with activity in last 30 min
  const since = new Date(Date.now() - 30 * 60_000).toISOString();
  const { data: jobs } = await db.from("scan_jobs").select("target_id").gte("created_at", since).limit(500);
  const { data: phases } = await db
    .from("scan_phase_state")
    .select("target_id")
    .gte("last_heartbeat", since)
    .limit(500);
  const set = new Set<string>();
  for (const j of jobs || []) if (j.target_id) set.add(j.target_id);
  for (const p of phases || []) if (p.target_id) set.add(p.target_id);
  return [...set];
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const db = createClient(SUPA, SVC);
    let body: any = {};
    try {
      body = await req.json();
    } catch {
      /* ignore */
    }

    // ── Diagnose + selective resume ──────────────────────────────────────
    // Reports, per phase, which specific modules (job_types) completed vs
    // never ran vs failed — not just the coarse phase-level status the
    // auto-advancer above tracks. If body.resume=true, re-queues ONLY the
    // caller-selected missing modules (or all missing ones if none
    // specified) instead of restarting the entire scan from recon.
    if (body.action === "diagnose" || body.action === "resume") {
      const targetId = body.targetId;
      if (!targetId) {
        return new Response(JSON.stringify({ ok: false, error: "targetId required" }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      const { data: phaseRows } = await db
        .from("scan_phase_state")
        .select("phase,status,last_heartbeat,started_at,completed_at")
        .eq("target_id", targetId);
      const phaseMap = new Map((phaseRows || []).map((p: any) => [p.phase, p]));

      const { data: jobRows } = await db
        .from("scan_jobs")
        .select("job_type,status,created_at,completed_at")
        .eq("target_id", targetId)
        .order("created_at", { ascending: false });

      // Latest status per job_type (jobs can be re-queued, so take most recent)
      const latestByType = new Map<string, any>();
      for (const j of jobRows || []) {
        if (!latestByType.has(j.job_type)) latestByType.set(j.job_type, j);
      }

      const report: Record<string, any> = {};
      const missingByPhase: Record<string, { type: string; priority: number; payload?: any }[]> = {};

      for (const phase of PHASES) {
        const phaseState: any = phaseMap.get(phase);
        const expectedJobs = PHASE_JOBS[phase] || [];
        const moduleStatus = expectedJobs.map((j) => {
          const latest = latestByType.get(j.type);
          const status = !latest ? "never_ran" : latest.status === "done" ? "completed" : latest.status;
          return {
            module: j.type,
            status,
            lastRunAt: latest?.created_at ?? null,
            completedAt: latest?.completed_at ?? null,
          };
        });
        const missing = moduleStatus.filter((m) => m.status === "never_ran" || m.status === "failed");
        report[phase] = {
          phaseStatus: phaseState?.status || "pending",
          modules: moduleStatus,
          missingCount: missing.length,
        };
        if (missing.length) {
          missingByPhase[phase] = expectedJobs.filter((j) => missing.some((m) => m.module === j.type));
        }
      }

      if (body.action === "diagnose") {
        return new Response(JSON.stringify({ ok: true, targetId, phases: report }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      // action === "resume": re-queue only what's missing (or the caller's
      // explicit module subset, e.g. ["subdomain_enum","chain"])
      const requestedModules: string[] | undefined = body.modules;
      const resumed: Record<string, number> = {};
      for (const [phase, jobs] of Object.entries(missingByPhase)) {
        const toQueue = requestedModules ? jobs.filter((j) => requestedModules.includes(j.type)) : jobs;
        if (!toQueue.length) continue;
        // Reset stale phase state so the auto-advancer doesn't think this
        // phase is still "complete" while modules within it are re-run.
        await db.from("scan_phase_state").upsert(
          {
            target_id: targetId,
            phase,
            status: "running",
            started_at: new Date().toISOString(),
            last_heartbeat: new Date().toISOString(),
          },
          { onConflict: "target_id,phase" },
        );
        const n = await enqueue(db, targetId, toQueue);
        if (n > 0) resumed[phase] = n;

        await db.from("scan_logs").insert({
          target_id: targetId,
          log_type: "info",
          message: `🔁 Scan resume: re-queued ${n} missing module(s) in ${phase} phase: ${toQueue.map((j) => j.type).join(", ")}`,
        });
      }

      return new Response(JSON.stringify({ ok: true, targetId, resumed, diagnosis: report }), {
        status: 200,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const targets: string[] = body.targetId ? [body.targetId] : await detectActiveTargets(db);
    const out: Record<string, string[]> = {};
    for (const t of targets.slice(0, 20)) {
      out[t] = await arbitrateTarget(db, t);
    }
    return new Response(JSON.stringify({ ok: true, arbitrated: out }), {
      status: 200,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: e instanceof Error ? e.message : "err" }), {
      status: 200,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
