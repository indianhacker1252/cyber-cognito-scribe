// ai-strategist — Cross-finding reasoning. Builds attack_hypotheses rows from
// the asset graph + existing findings + tech stack via Lovable AI Gateway.
// Each hypothesis becomes a hypothesis_test scan_job.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { logAiNextStep } from "../_shared/ai-next-step.ts";
import { llmCall, tryParseJson } from "../_shared/llm.ts";
import { enqueueJobs } from "../_shared/enqueue.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

const SUPA = Deno.env.get("SUPABASE_URL")!;
const SVC = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

interface Hypothesis {
  asset_host?: string;
  endpoint_url?: string;
  method?: string;
  vuln_class?: string;
  hypothesis: string;
  mutation?: any;
  expected_proof?: string;
}

async function generateHypotheses(db: any, targetId: string, context: any): Promise<{ hypotheses: Hypothesis[]; provider: string; error?: string }> {
  const proofNonce = Math.random().toString(36).slice(2, 10).toUpperCase(); // e.g. "X4K9P2QR"
  const prompt = `You are XBOW-tier offensive AI — reviewing a target's full recon + evidence trail. Compete with Mythos + XBOW on chain-depth.

═══ ASSET GRAPH (subdomains + tech) ═══
${JSON.stringify((context.assets || []).slice(0, 30))}

═══ PROVEN FINDINGS (exploited tier — reuse these primitives) ═══
${JSON.stringify((context.provenFindings || []).slice(0, 15))}

═══ ALL FINDINGS (signal + suspected) ═══
${JSON.stringify((context.findings || []).slice(0, 40))}

═══ DISCOVERED ENDPOINTS (unfuzzed candidates) ═══
${JSON.stringify((context.endpoints || []).slice(0, 30))}

═══ TECH STACK ═══
${JSON.stringify(context.techStack || {})}

═══ WAF PROFILE ═══
${JSON.stringify(context.wafProfile || {})}

═══ OOB CALLBACKS OBSERVED ═══
${context.oobCount || 0}

═══ RECENT AGENT DECISIONS (last 10 log lines) ═══
${(context.recentDecisions || [])
  .slice(0, 10)
  .map((l: any) => `- [${l.log_type}] ${l.message}`)
  .join("\n")}

Generate up to 12 high-value attack hypotheses we have NOT tested yet.
For each, output strict JSON in this schema:
{ "asset_host": "...", "endpoint_url": "...", "method": "GET|POST|...", "vuln_class": "xss|sqli|ssrf|ssti|idor|auth_bypass|open-redirect|...", "hypothesis": "one-sentence reasoning", "mutation": { "param": "...", "payload": "..." }, "expected_proof": "PROOF_STRING" }

CRITICAL — expected_proof rules (violation = useless finding):
- Must be a STRING that will appear in the HTTP response IF AND ONLY IF the vulnerability exists.
- Must be UNIQUE: use the nonce "${proofNonce}" embedded in your payload so only your specific test produces it.
  Example for XSS: payload="<img src=x onerror=alert('${proofNonce}')>", expected_proof="${proofNonce}"
  Example for SSTI: payload="{{${proofNonce.charCodeAt(0)}*${proofNonce.charCodeAt(1)}}}", expected_proof=(product of the two char codes)
  Example for SQLi: payload="' AND '${proofNonce}'='${proofNonce}", expected_proof="${proofNonce}"
  Example for SSRF: payload="http://oob-host/?t=${proofNonce}", expected_proof="${proofNonce}" (requires OOB callback)
  Example for blind-SQLi: payload="' AND SLEEP(5)--", expected_proof="TIMING:>4000ms"
- NEVER use generic words: "admin", "true", "200", "success", "error", "found", "ok", "user", "null".
- If you cannot construct a unique detectable proof for a vuln class, omit expected_proof entirely.

Focus on:
- CHAINING proven primitives (e.g. exploited XSS on subA → cookie steal → IDOR on subB).
- Forgotten admin/dev subdomains with default creds.
- Tech-specific CVE plays based on detected stack.
- Parameter names typical for the framework that we haven't fuzzed yet.
- Auth-adjacent endpoints (JWT, oauth, /admin, /api/v*/users).

Output ONLY a JSON array of hypothesis objects. No prose.`;

  const out = await llmCall({
    db,
    targetId,
    phase: "ai-strategist",
    temperature: 0.6,
    maxTokens: 3000,
    messages: [
      { role: "system", content: "Return only a strict JSON array. No prose, no markdown." },
      { role: "user", content: prompt },
    ],
  });
  if (!out.ok || !out.text) return { hypotheses: [], provider: out.provider, error: out.error || "empty_output" };
  const parsed = tryParseJson<unknown>(out.text) ?? (() => {
    const m = out.text.match(/\[[\s\S]*\]/);
    if (!m) return null;
    try { return JSON.parse(m[0]); } catch { return null; }
  })();
  const arr = Array.isArray(parsed) ? parsed : [];
  return { hypotheses: arr.slice(0, 15) as Hypothesis[], provider: out.provider };
}

async function strategize(db: any, targetId: string, round: number) {
  const [
    { data: assets },
    { data: findings },
    { data: proven },
    { data: endpoints },
    { data: tgt },
    { data: oob },
    { data: recentDecisions },
  ] = await Promise.all([
    db.from("scan_assets").select("host,base_url,source").eq("target_id", targetId).limit(50),
    db
      .from("vulnerability_findings")
      .select("vuln_class,finding_type,severity,affected_url,proof_tier")
      .eq("target_id", targetId)
      .limit(80),
    db
      .from("vulnerability_findings")
      .select("title,vuln_class,severity,affected_url,payload,hard_evidence")
      .eq("target_id", targetId)
      .eq("proof_tier", "exploited")
      .limit(20),
    db.from("discovered_endpoints").select("url,method,parameters").eq("target_id", targetId).limit(60),
    db.from("target_workspaces").select("domain,waf_profile").eq("id", targetId).maybeSingle(),
    db.from("oob_callbacks").select("id", { count: "exact", head: true }).eq("target_id", targetId),
    db
      .from("scan_logs")
      .select("log_type,message")
      .eq("target_id", targetId)
      .in("log_type", ["action", "warning", "result", "thought"])
      .order("created_at", { ascending: false })
      .limit(20),
  ]);

  const techStack: Record<string, string> = {};
  // Best-effort: pull most-recent tech from scan_logs
  try {
    const { data: techLogs } = await db
      .from("scan_logs")
      .select("metadata")
      .eq("target_id", targetId)
      .eq("log_type", "info")
      .order("created_at", { ascending: false })
      .limit(20);
    for (const t of techLogs || []) {
      const m = t.metadata as any;
      if (m?.tech) Object.assign(techStack, m.tech);
    }
  } catch {
    /* ignore */
  }

  const ctx = {
    assets: assets || [],
    findings: findings || [],
    provenFindings: proven || [],
    endpoints: endpoints || [],
    techStack,
    wafProfile: tgt?.waf_profile || {},
    oobCount: oob ?? 0,
    recentDecisions: recentDecisions || [],
  };

  const ai = await generateHypotheses(db, targetId, ctx);
  const hyps = ai.hypotheses.filter((h) => h?.hypothesis && (h.endpoint_url || h.asset_host)).slice(0, 15);
  if (!hyps.length) {
    await db
      .from("scan_logs")
      .insert({
        target_id: targetId,
        log_type: "warn",
        message: `🧠 ai-strategist round ${round}: no hypotheses generated (${ai.provider}${ai.error ? `: ${ai.error}` : ""})`,
        metadata: { kind: "ai_strategist_empty", round, provider: ai.provider, error: ai.error },
      })
      .then(
        () => {},
        () => {},
      );
    return { generated: 0 };
  }

  const rows = hyps.map((h) => ({
    target_id: targetId,
    round,
    asset_host: h.asset_host || null,
    endpoint_url: h.endpoint_url || null,
    method: h.method || "GET",
    vuln_class: h.vuln_class || null,
    hypothesis: h.hypothesis,
    mutation: h.mutation || {},
    expected_proof: h.expected_proof || null,
    status: "pending",
  }));

  const inserted = await db
    .from("attack_hypotheses")
    .insert(hyps.map((h) => ({ target_id: targetId, ...h, status: "pending", round })))
    .select("id");

  // Schedule each hypothesis as a job
  const jobs = (inserted.data || []).map((h) => ({
    target_id: targetId,
    job_type: "hypothesis_test",
    priority: 7,
    payload: { hypothesisId: h.id },
    next_run_at: new Date().toISOString(),
    dedupWindowMs: 60 * 60_000,
    dedupExtraKey: h.id,
  }));
  if (jobs.length) await enqueueJobs(db, jobs);

  // Structured "AI next step" entries — one per queued hypothesis, so Neural
  // Logs can show exactly what the AI debated and what it decided to run
  // next, instead of just a plain "N hypotheses generated" count.
  for (const h of rows.slice(0, jobs.length)) {
    await logAiNextStep(db, {
      targetId,
      decisionType: "hypothesis-selection",
      debating: h.hypothesis,
      reasoningSummary: `Round ${round}: chose to test ${h.vuln_class || "unclassified"} on ${h.endpoint_url || h.asset_host || "target"} based on recon/findings context`,
      nextStep: {
        tool: "hypothesis-test-runner",
        action: `test ${h.vuln_class || "vuln"} via ${h.mutation?.param ? `param "${h.mutation.param}"` : "mutation"}`,
        targetUrl: h.endpoint_url,
        vulnClass: h.vuln_class,
      },
      extra: { round },
    });
  }
  if (rows.length === 0) {
    await logAiNextStep(db, {
      targetId,
      decisionType: "hypothesis-selection",
      debating: `whether any high-value untested attack surface remains after round ${round}`,
      reasoningSummary:
        "No viable hypotheses generated from current recon/findings context — likely need more recon depth or the surface is exhausted",
      nextStep: null,
      extra: { round },
    });
  }

  await db.from("scan_logs").insert({
    target_id: targetId,
    log_type: "action",
    message: `🧠 AI Strategist queued ${jobs.length} hypothesis tests from round ${round}`,
  });

  await db
    .from("scan_logs")
    .insert({
      target_id: targetId,
      log_type: "action",
      message: `🧠 ai-strategist round ${round}: ${rows.length} hypotheses generated`,
      metadata: { kind: "ai_strategist", round, count: rows.length, provider: ai.provider },
    })
    .then(
      () => {},
      () => {},
    );

  return { generated: rows.length };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const db = createClient(SUPA, SVC);
    const body = await req.json().catch(() => ({}));
    const { targetId, round = 1 } = body;
    if (!targetId) {
      return new Response(JSON.stringify({ ok: false, error: "targetId required" }), {
        status: 200,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
    // Run in background to dodge gateway 150s timeout
    const work = strategize(db, targetId, round);
    // @ts-ignore EdgeRuntime is available
    if (typeof EdgeRuntime !== "undefined" && (EdgeRuntime as any).waitUntil) {
      // @ts-ignore
      (EdgeRuntime as any).waitUntil(work);
      return new Response(JSON.stringify({ ok: true, accepted: true }), {
        status: 202,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
    const out = await work;
    return new Response(JSON.stringify({ ok: true, ...out }), {
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
