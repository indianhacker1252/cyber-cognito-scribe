// ai-strategist — Cross-finding reasoning. Builds attack_hypotheses rows from
// the asset graph + existing findings + tech stack via Lovable AI Gateway.
// Each hypothesis becomes a hypothesis_test scan_job.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

const SUPA = Deno.env.get("SUPABASE_URL")!;
const SVC = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const LOVABLE_AI_KEY = Deno.env.get("LOVABLE_API_KEY")!;

interface Hypothesis {
  asset_host?: string;
  endpoint_url?: string;
  method?: string;
  vuln_class?: string;
  hypothesis: string;
  mutation?: any;
  expected_proof?: string;
}

async function generateHypotheses(context: any): Promise<Hypothesis[]> {
  if (!LOVABLE_AI_KEY) return [];
  const prompt = `You are a senior offensive security engineer reviewing a target's recon + findings.

Asset graph (subdomains): ${JSON.stringify((context.assets || []).slice(0, 20))}
Existing findings (summary): ${JSON.stringify((context.findings || []).slice(0, 30))}
Tech stack: ${JSON.stringify(context.techStack || {})}
WAF profile: ${JSON.stringify(context.wafProfile || {})}
OOB callbacks observed: ${context.oobCount || 0}

Generate up to 12 high-value attack hypotheses we have NOT tested yet.
For each, output strict JSON in this schema:
{ "asset_host": "...", "endpoint_url": "...", "method": "GET|POST|...", "vuln_class": "xss|sqli|ssrf|ssti|idor|...", "hypothesis": "one-sentence reasoning", "mutation": { "param": "...", "payload": "..." }, "expected_proof": "what string in response proves it" }

Focus on:
- Combining findings (e.g. open-redirect on subA + SSRF param on subB → chained ATO).
- Forgotten admin/dev subdomains.
- Tech-specific CVE plays based on detected stack.
- Parameter names typical for the framework that we haven't fuzzed yet.

Output ONLY a JSON array of hypothesis objects. No prose.`;

  try {
    const r = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Lovable-API-Key": LOVABLE_AI_KEY },
      body: JSON.stringify({
        model: "google/gemini-2.5-flash",
        messages: [{ role: "user", content: prompt }],
        temperature: 0.6,
      }),
      signal: AbortSignal.timeout(40_000),
    });
    if (!r.ok) return [];
    const j = await r.json();
    const txt = j?.choices?.[0]?.message?.content || "";
    const m = txt.match(/\[[\s\S]*\]/);
    if (!m) return [];
    const arr = JSON.parse(m[0]);
    return Array.isArray(arr) ? arr.slice(0, 15) : [];
  } catch { return []; }
}

async function strategize(db: any, targetId: string, round: number) {
  const [{ data: assets }, { data: findings }, { data: tgt }, { data: oob }] = await Promise.all([
    db.from("scan_assets").select("host,base_url,source").eq("target_id", targetId).limit(50),
    db.from("vulnerability_findings").select("vuln_class,finding_type,severity,affected_url,proof_tier").eq("target_id", targetId).limit(80),
    db.from("target_workspaces").select("domain,waf_profile").eq("id", targetId).maybeSingle(),
    db.from("oob_callbacks").select("id", { count: "exact", head: true }).eq("target_id", targetId),
  ]);

  const techStack: Record<string, string> = {};
  // Best-effort: pull most-recent tech from scan_logs
  try {
    const { data: techLogs } = await db.from("scan_logs")
      .select("metadata").eq("target_id", targetId).eq("log_type", "info")
      .order("created_at", { ascending: false }).limit(20);
    for (const t of techLogs || []) {
      const m = t.metadata as any;
      if (m?.tech) Object.assign(techStack, m.tech);
    }
  } catch { /* ignore */ }

  const ctx = {
    assets: assets || [],
    findings: findings || [],
    techStack,
    wafProfile: tgt?.waf_profile || {},
    oobCount: oob ?? 0,
  };

  const hyps = await generateHypotheses(ctx);
  if (!hyps.length) {
    await db.from("scan_logs").insert({
      target_id: targetId, log_type: "warn",
      message: `🧠 ai-strategist round ${round}: no hypotheses generated (AI gateway empty/error)`,
      metadata: { kind: "ai_strategist_empty", round },
    }).then(() => {}, () => {});
    return { generated: 0 };
  }

  const rows = hyps.map(h => ({
    target_id: targetId, round,
    asset_host: h.asset_host || null,
    endpoint_url: h.endpoint_url || null,
    method: h.method || "GET",
    vuln_class: h.vuln_class || null,
    hypothesis: h.hypothesis,
    mutation: h.mutation || {},
    expected_proof: h.expected_proof || null,
    status: "pending",
  }));
  const { data: inserted } = await db.from("attack_hypotheses").insert(rows).select("id");

  // Queue a hypothesis_test job per hypothesis
  const now = new Date().toISOString();
  const jobs = (inserted || []).map((row: any) => ({
    target_id: targetId, job_type: "hypothesis_test", status: "queued",
    priority: 7, payload: { hypothesisId: row.id }, next_run_at: now,
  }));
  if (jobs.length) await db.from("scan_jobs").insert(jobs).then(() => {}, () => {});

  await db.from("scan_logs").insert({
    target_id: targetId, log_type: "action",
    message: `🧠 ai-strategist round ${round}: ${rows.length} hypotheses generated`,
    metadata: { kind: "ai_strategist", round, count: rows.length },
  }).then(() => {}, () => {});

  return { generated: rows.length };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const db = createClient(SUPA, SVC);
    const body = await req.json().catch(() => ({}));
    const { targetId, round = 1 } = body;
    if (!targetId) {
      return new Response(JSON.stringify({ ok: false, error: "targetId required" }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    // Run in background to dodge gateway 150s timeout
    const work = strategize(db, targetId, round);
    // @ts-ignore EdgeRuntime is available
    if (typeof EdgeRuntime !== "undefined" && (EdgeRuntime as any).waitUntil) {
      // @ts-ignore
      (EdgeRuntime as any).waitUntil(work);
      return new Response(JSON.stringify({ ok: true, accepted: true }),
        { status: 202, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    const out = await work;
    return new Response(JSON.stringify({ ok: true, ...out }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: e instanceof Error ? e.message : "err" }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
