// Pillar 3: Long-horizon Mythos agent loop. Orchestrates all pillars in iterations.
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

async function call(fn: string, body: any) {
  const r = await fetch(`${SUPABASE_URL}/functions/v1/${fn}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${SERVICE_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await r.text();
  try { return { ok: r.ok, data: JSON.parse(text) }; } catch { return { ok: r.ok, data: { raw: text } }; }
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });
  try {
    const { targetId, triggerType = "manual", maxIterations = 8, repoUrl } = await req.json();
    if (!targetId) throw new Error("targetId required");

    const db = createClient(SUPABASE_URL, SERVICE_KEY);

    // Bail early if AI credits are exhausted — mythos is 100% LLM-driven, so
    // running it without any working provider just spams "🪫" error rows.
    const { areCreditsRecentlyExhausted } = await import("../_shared/ai-credits.ts");
    if (await areCreditsRecentlyExhausted(db, targetId, 15)) {
      await db.from("scan_logs").insert({
        target_id: targetId, log_type: "warning",
        message: "🧠 Mythos paused: AI credits exhausted and no fallback provider configured. Add OPENAI_API_KEY / GEMINI_API_KEY / ANTHROPIC_API_KEY or top up Lovable AI, then re-trigger.",
        metadata: { kind: "mythos_paused_no_ai" },
      });
      return new Response(JSON.stringify({ ok: false, paused: true, reason: "no_ai_provider" }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // Loop-guard: mythos-agent ran 100+ times per target — cap it.
    const { checkLoopGuard, recordLoopRun } = await import("../_shared/loop-guard.ts");
    const _mg = await checkLoopGuard(db, targetId, "mythos-agent", { maxRuns: 3, stallStreak: 2, windowMinutes: 60 });
    if (!_mg.allow) {
      return new Response(JSON.stringify({ ok: false, skipped: true, reason: _mg.reason }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const { data: run, error: runErr } = await db.from("mythos_runs").insert({
      target_id: targetId, trigger_type: triggerType, max_iterations: maxIterations,
      status: "running", started_at: new Date().toISOString(), current_phase: "init",
    }).select().single();
    if (runErr) throw runErr;
    const runId = run.id;

    const log: any[] = [];
    const append = async (phase: string, msg: string, extra: any = {}) => {
      log.push({ ts: new Date().toISOString(), phase, msg, ...extra });
      await db.from("mythos_runs").update({ thought_log: log, current_phase: phase }).eq("id", runId);
      await db.from("scan_logs").insert({ target_id: targetId, log_type: "info", message: `🧠 Mythos[${phase}]: ${msg}`, metadata: { run_id: runId, ...extra } });
    };

    let totalFindings = 0, totalChains = 0, totalVariants = 0;

    // Phase 1: SAST (if repo provided)
    if (repoUrl) {
      await append("sast", `Ingesting source from ${repoUrl}`);
      const r = await call("mythos-codebase-ingest", { targetId, repoUrl });
      if (r.ok) {
        totalFindings += r.data.findingsCount || 0;
        await append("sast", `Found ${r.data.findingsCount} taint flows in ${r.data.fileCount} files`, { sast_findings: r.data.findingsCount });
      } else {
        await append("sast", `SAST failed: ${JSON.stringify(r.data).slice(0, 200)}`);
      }
    }

    // Phase 2: iterative chain + variant + debate loop
    for (let i = 1; i <= maxIterations; i++) {
      await db.from("mythos_runs").update({ iteration: i }).eq("id", runId);
      await append(`iter-${i}`, `Iteration ${i}/${maxIterations} starting`);

      // Idempotency lock: skip if this iteration's debate phase already started
      const debatePhaseKey = `debate-${i}-${runId}`;
      const { data: alreadyRunning } = await db.from("scan_logs")
        .select("id").eq("target_id", targetId)
        .like("message", `%${debatePhaseKey}%`).limit(1);
      if (alreadyRunning && alreadyRunning.length > 0) {
        await append(`iter-${i}-debate`, "⚠️ Debate phase already running — skipping duplicate");
        continue;
      }
      await db.from("scan_logs").insert({
        target_id: targetId, log_type: "info",
        message: `debate-lock:${debatePhaseKey}`,
        metadata: { run_id: runId },
      });



      // Chainer
      await append(`iter-${i}-chain`, `🔗 Asking LLM to propose kill-chains from current findings`);
      const chainRes = await call("mythos-chainer", { targetId, runId });
      if (chainRes.ok) {
        const c = chainRes.data.chainsCount || 0;
        totalChains += c;
        await append(`iter-${i}-chain`, `Chainer proposed ${c} kill-chains`, { chains: c });
      }

      // Variant gen (now queues per-payload tests)
      await append(`iter-${i}-variant`, `🌀 Generating zero-day variants from CVE root causes`);
      const varRes = await call("mythos-variant-gen", { targetId, runId });
      if (varRes.ok) {
        const v = varRes.data.variantsCount || 0;
        const cand = varRes.data.candidates || 0;
        totalVariants += v;
        await append(`iter-${i}-variant`, `Generated ${v} variants, ${cand} immediate 0-day candidates`, { variants: v, candidates: cand });
      }

      // Debate phase: pick top N suspicious params and run two-agent debate
      await append(`iter-${i}-debate`, `🥷 Two-agent black-hat debate on top params`);
      const { data: eps } = await db.from("discovered_endpoints")
        .select("url,method,parameters").eq("target_id", targetId).limit(50);
      let debatesRun = 0, fpEliminated = 0, tpConfirmed = 0;
      const COMMON_PARAMS = ["q", "id", "search", "query", "email", "user", "page", "url", "redirect"];
      // Fix #7 — dedupe params across iterations so we don't re-test the same (url, param) pair
      const alreadyDebated: Set<string> = (globalThis as any).__mythos_debated__ ||= new Set();
      for (const ep of (eps || [])) {
        // accept stored params, URL params, then common-name fallbacks.
        let params = (ep.parameters as Record<string, string>) || {};
        if (Object.keys(params).length === 0) {
          try {
            const urlParams = new URL(ep.url).searchParams;
            params = Object.fromEntries(urlParams);
          } catch { /* ignore parse errors */ }
        }
        // Fix #9 — skip GET param testing on POST-only endpoints (would send wrong-method probes)
        const isPostOnly = (ep.method || "GET").toUpperCase() === "POST" && Object.keys(params).length === 0;
        if (isPostOnly) continue;
        if (Object.keys(params).length === 0) {
          params = Object.fromEntries(COMMON_PARAMS.map((p) => [p, "test"]));
        }
        const paramKeys = Object.keys(params).slice(0, 3);
        for (const pk of paramKeys) {
          const dedupKey = `${ep.url}::${pk}`;
          if (alreadyDebated.has(dedupKey)) continue;
          alreadyDebated.add(dedupKey);
          const dRes = await call("mythos-debate", {
            targetId, runId, endpointUrl: ep.url, paramName: pk,
            paramValue: params[pk], vulnClassHint: "auto",
          });
          if (dRes.ok) {
            debatesRun++;
            if (dRes.data.fpVerdict === "false_positive") fpEliminated++;
            if (dRes.data.fpVerdict === "true_positive") tpConfirmed++;
          }
          if (debatesRun >= 20) break;
        }
        if (debatesRun >= 20) break;
      }
      await append(`iter-${i}-debate`, `Debates: ${debatesRun} run, ${tpConfirmed} TP, ${fpEliminated} FP eliminated (${alreadyDebated.size} unique pairs tested so far)`, { debatesRun, tpConfirmed, fpEliminated });

      // Stop early if nothing new
      if ((chainRes.data?.chainsCount ?? 0) === 0 && (varRes.data?.candidates ?? 0) === 0 && debatesRun === 0 && i >= 2) {
        await append(`iter-${i}`, `No new attack surface — stopping early`);
        break;
      }
    }

    // Phase 3: auto-patch top 3 findings
    await append("patch", "Generating defensive patches for top findings");
    const { data: topFindings } = await db.from("vulnerability_findings")
      .select("id").eq("target_id", targetId).order("cvss_score", { ascending: false, nullsFirst: false }).limit(3);
    for (const f of topFindings || []) {
      await call("mythos-patcher", { findingId: f.id, targetId });
    }

    await db.from("mythos_runs").update({
      status: "complete", completed_at: new Date().toISOString(), current_phase: "done",
      findings_count: totalFindings, chains_count: totalChains, variants_count: totalVariants,
    }).eq("id", runId);

    await append("done", `Run complete: ${totalFindings} SAST findings, ${totalChains} chains, ${totalVariants} variants`);

    return new Response(JSON.stringify({ runId, totalFindings, totalChains, totalVariants }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (e) {
    console.error(e);
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : String(e) }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
