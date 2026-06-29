// hypothesis-test-runner — executes one attack_hypotheses row: fires the
// proposed mutation against the endpoint, checks for expected_proof, and
// records a finding on match.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { recordFinding } from "../_shared/findings-writer.ts";
import { loadJar, applyJar } from "../_shared/session-jar.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

const SUPA = Deno.env.get("SUPABASE_URL")!;
const SVC = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

async function safeFetch(url: string, init: RequestInit, ms = 8000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try { return await fetch(url, { ...init, signal: ctrl.signal }); }
  finally { clearTimeout(t); }
}

async function runOne(db: any, hypothesisId: string) {
  const { data: h } = await db.from("attack_hypotheses").select("*").eq("id", hypothesisId).maybeSingle();
  if (!h) return { ok: false, error: "hypothesis not found" };
  await db.from("attack_hypotheses").update({ status: "running" }).eq("id", hypothesisId);

  const url = h.endpoint_url;
  if (!url) {
    await db.from("attack_hypotheses").update({ status: "skipped", result: { reason: "no endpoint_url" } }).eq("id", hypothesisId);
    return { ok: false, error: "no endpoint" };
  }

  const jar = await loadJar(db, h.target_id);
  const mutation = (h.mutation || {}) as { param?: string; payload?: string; header?: Record<string, string>; body?: string };
  let targetUrl = url, init: RequestInit = { method: h.method || "GET" };
  try {
    const u = new URL(url);
    if (mutation.param && mutation.payload !== undefined) {
      u.searchParams.set(mutation.param, mutation.payload);
    }
    targetUrl = u.toString();
  } catch { /* ignore */ }
  const headers: Record<string, string> = { "User-Agent": "CyberScope/strategist", ...(mutation.header || {}) };
  init.headers = applyJar(jar, headers);
  if (h.method && /^(POST|PUT|PATCH|DELETE)$/i.test(h.method) && mutation.body) {
    init.body = mutation.body;
    (init.headers as any)["Content-Type"] = (init.headers as any)["Content-Type"] || "application/x-www-form-urlencoded";
  }

  let status = 0, body = "", err = "";
  try {
    const r = await safeFetch(targetUrl, init, 10_000);
    status = r.status;
    body = (await r.text().catch(() => "")).slice(0, 8000);
  } catch (e) { err = e instanceof Error ? e.message : "err"; }

  const expected = (h.expected_proof || "").trim();
  const proofHit = expected ? body.includes(expected) || /CYBERSCOPE_PROVEN/.test(body) : false;

  const result = { status, length: body.length, proofHit, snippet: body.slice(0, 600), err };
  let findingId: string | undefined;

  if (proofHit) {
    const rec = await recordFinding({
      targetId: h.target_id,
      source: "ai-strategist",
      vulnClass: h.vuln_class || "generic",
      category: h.vuln_class || "ai-strategist",
      severity: "high",
      title: `[AI-Strategist] ${h.vuln_class || "vuln"} proven via hypothesis`,
      description: h.hypothesis,
      payload: mutation.payload || "",
      proofTier: "exploited",
      autoEnqueueExploit: true,
      evidence: { hypothesisId, expected_proof: expected, asset: h.asset_host, vuln_class: h.vuln_class, affected_url: targetUrl, snippet: body.slice(0, 800) },
      request: { method: h.method || "GET", url: targetUrl, headers: headers, body: typeof init.body === "string" ? init.body : undefined },
      response: { status, body: body.slice(0, 4000) },
    });
    findingId = rec.findingId;
  }

  await db.from("attack_hypotheses").update({
    status: proofHit ? "confirmed" : "tested",
    result, finding_id: findingId || null,
  }).eq("id", hypothesisId);

  return { ok: true, proofHit, findingId };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const db = createClient(SUPA, SVC);
    const body = await req.json().catch(() => ({}));
    const { hypothesisId } = body;
    if (!hypothesisId) {
      return new Response(JSON.stringify({ ok: false, error: "hypothesisId required" }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    const out = await runOne(db, hypothesisId);
    return new Response(JSON.stringify(out), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: e instanceof Error ? e.message : "err" }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
