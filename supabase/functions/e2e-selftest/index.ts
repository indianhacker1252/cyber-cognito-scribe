// E2E Self-Test — runs the kill-path against a legal public test target and
// asserts the pipeline produced findings, exploits, fan-out, methods coverage,
// form/upload tests, and kill-chain depth.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};
const SUPA = Deno.env.get("SUPABASE_URL")!;
const SVC = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const db = () => createClient(SUPA, SVC);

async function call(fn: string, body: any, ms = 45000) {
  try {
    const r = await fetch(`${SUPA}/functions/v1/${fn}`, {
      method: "POST",
      headers: { Authorization: `Bearer ${SVC}`, "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(ms),
    });
    const t = await r.text();
    try { return { ok: r.ok, data: JSON.parse(t) }; } catch { return { ok: r.ok, data: { raw: t } }; }
  } catch (e) { return { ok: false, data: { error: e instanceof Error ? e.message : "err" } }; }
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  const ok = (b: any) => new Response(JSON.stringify(b), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });

  const supa = db();
  const body = await req.json().catch(() => ({} as any));
  const rawUrl = body.url || "testphp.vulnweb.com";
  const testUrl = rawUrl.replace(/^https?:\/\//, "").replace(/\/+$/, "");

  // 1. Create / fetch sentinel target
  const { data: existing } = await supa.from("target_workspaces").select("id").eq("domain", testUrl).maybeSingle();
  let targetId = existing?.id;
  if (!targetId) {
    // Pick any existing user to own the sentinel target (schema requires user_id)
    const { data: anyProfile } = await supa.from("profiles").select("id").limit(1).maybeSingle();
    if (!anyProfile?.id) return ok({ ok: false, error: "no user in profiles to own sentinel target" });
    const { data: inserted, error } = await supa.from("target_workspaces").insert({
      name: "E2E SelfTest Target",
      domain: testUrl,
      user_id: anyProfile.id,
      attestation_accepted: true,
      attestation_accepted_at: new Date().toISOString(),
      authorization_mode: "attestation",
    }).select("id").single();
    if (error) return ok({ ok: false, error: error.message });
    targetId = inserted.id;
  }

  await supa.from("scan_logs").insert({
    target_id: targetId, log_type: "action",
    message: `🧪 E2E SelfTest v2 started against ${testUrl}`,
  });

  // 2. Drive the full kill-path (recon → fan-out fuzz → forms → AI fuzz)
  const reconR = await call("recon-engine", { targetId }, 35000);
  const matrixR = await call("matrix-fuzzer", { targetId, perAssetCap: 40 }, 45000);
  const formR = await call("form-attacker", { targetId }, 40000);
  const fuzzR = await call("advanced-fuzzer", { targetId }, 45000);

  // Drain queue
  await new Promise(r => setTimeout(r, 3000));
  await call("scan-job-worker", {}, 30000);
  await new Promise(r => setTimeout(r, 2000));

  // 3. Assertions
  const since = new Date(Date.now() - 10 * 60_000).toISOString();
  const [
    { count: epCount },
    { count: findCount },
    { count: exploitedCount },
    { count: oobCount },
    { count: exploitRuns },
    { count: assetCount },
    { count: formsCount },
    { count: chainEdges },
    { data: matrixLogs },
  ] = await Promise.all([
    supa.from("discovered_endpoints").select("id", { count: "exact", head: true }).eq("target_id", targetId),
    supa.from("vulnerability_findings").select("id", { count: "exact", head: true }).eq("target_id", targetId).gte("created_at", since),
    supa.from("vulnerability_findings").select("id", { count: "exact", head: true }).eq("target_id", targetId).eq("proof_tier", "exploited"),
    supa.from("oob_callbacks").select("id", { count: "exact", head: true }).eq("target_id", targetId),
    supa.from("exploit_runs").select("id", { count: "exact", head: true }).eq("target_id", targetId),
    supa.from("scan_assets").select("id", { count: "exact", head: true }).eq("target_id", targetId),
    supa.from("discovered_forms").select("id", { count: "exact", head: true }).eq("target_id", targetId),
    supa.from("kill_chain_graph_edges").select("id", { count: "exact", head: true }).eq("target_id", targetId),
    supa.from("scan_logs").select("metadata").eq("target_id", targetId).ilike("message", "%Matrix-fuzzer done%").order("created_at", { ascending: false }).limit(1),
  ]);

  const methodsTested = (matrixLogs?.[0] as any)?.metadata?.methods?.length ?? (matrixR.data?.methodsTested?.length ?? 0);
  const probesSent = matrixR.data?.probesSent ?? (matrixLogs?.[0] as any)?.metadata?.probesSent ?? 0;

  const assertions: Record<string, { pass: boolean; actual: number | string }> = {
    endpoints_ge_5: { pass: (epCount ?? 0) >= 5, actual: epCount ?? 0 },
    assets_scanned_ge_2: { pass: (assetCount ?? 0) >= 2, actual: assetCount ?? 0 },
    methods_tested_ge_3: { pass: methodsTested >= 3, actual: methodsTested },
    probes_sent_ge_20: { pass: probesSent >= 20, actual: probesSent },
    forms_harvested_ge_1: { pass: (formsCount ?? 0) >= 1, actual: formsCount ?? 0 },
    findings_ge_1: { pass: (findCount ?? 0) >= 1, actual: findCount ?? 0 },
    exploited_ge_1: { pass: (exploitedCount ?? 0) >= 1, actual: exploitedCount ?? 0 },
    exploit_runs_ge_1: { pass: (exploitRuns ?? 0) >= 1, actual: exploitRuns ?? 0 },
    oob_callbacks_ge_1: { pass: (oobCount ?? 0) >= 1, actual: oobCount ?? 0 },
    chain_edges_ge_1: { pass: (chainEdges ?? 0) >= 1, actual: chainEdges ?? 0 },
  };
  const allPass = Object.values(assertions).every(a => a.pass);

  for (const [k, v] of Object.entries(assertions)) {
    if (!v.pass) {
      await supa.from("scan_logs").insert({
        target_id: targetId, log_type: "error",
        message: `❌ E2E SelfTest failed: ${k} (actual=${v.actual})`,
        metadata: { kind: "e2e_assertion_failed", assertion: k, actual: v.actual },
      }).then(() => {}, () => {});
    }
  }
  await supa.from("scan_logs").insert({
    target_id: targetId, log_type: allPass ? "result" : "error",
    message: allPass
      ? `✅ E2E SelfTest v2 passed all ${Object.keys(assertions).length} assertions`
      : `❌ E2E SelfTest v2 failed — see prior errors`,
    metadata: { assertions, matrix: matrixR.data, form: formR.data, recon: reconR.data, fuzz: fuzzR.data },
  });

  return ok({ ok: true, allPass, assertions, targetId, testUrl,
    summary: { matrix: matrixR.data, form: formR.data } });
});
