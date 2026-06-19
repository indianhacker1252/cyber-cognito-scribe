// E2E Self-Test — runs the kill-path against a legal public test target and
// asserts the pipeline actually produced findings, exploits, and OOB callbacks.
// Triggered manually from SystemHealth → "Run E2E Self-Test".
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

  const supa = db();
  const rawUrl = body.url || "testphp.vulnweb.com";
  const testUrl = rawUrl.replace(/^https?:\/\//, "").replace(/\/+$/, "");

  // 1. Create / fetch a sentinel target
  const { data: existing } = await supa.from("target_workspaces").select("id").eq("domain", testUrl).maybeSingle();
  let targetId = existing?.id;
  if (!targetId) {
    const { data: inserted, error } = await supa.from("target_workspaces").insert({
      name: "E2E SelfTest Target",
      domain: testUrl,
      attestation_accepted: true,
      attestation_accepted_at: new Date().toISOString(),
      authorization_mode: "attestation",
    }).select("id").single();
    if (error) {
      return new Response(JSON.stringify({ ok: false, error: error.message }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" }, status: 200 });
    }
    targetId = inserted.id;
  }

  await supa.from("scan_logs").insert({
    target_id: targetId, log_type: "action",
    message: `🧪 E2E SelfTest started against ${testUrl}`,
  });

  // 2. Run recon → fuzz inline (best-effort, no awaiting the whole chain)
  const reconR = await call("recon-engine", { targetId }, 30000);
  const fuzzR = await call("advanced-fuzzer", { targetId }, 45000);

  // 3. Wait briefly for queue workers to drain
  await new Promise(r => setTimeout(r, 4000));
  await call("scan-job-worker", {}, 30000);
  await new Promise(r => setTimeout(r, 2000));

  // 4. Assertions
  const since = new Date(Date.now() - 5 * 60_000).toISOString();
  const [{ count: epCount }, { count: findCount }, { count: exploitedCount }, { count: oobCount }, { count: exploitRuns }] = await Promise.all([
    supa.from("discovered_endpoints").select("id", { count: "exact", head: true }).eq("target_id", targetId),
    supa.from("vulnerability_findings").select("id", { count: "exact", head: true }).eq("target_id", targetId).gte("created_at", since),
    supa.from("vulnerability_findings").select("id", { count: "exact", head: true }).eq("target_id", targetId).eq("proof_tier", "exploited"),
    supa.from("oob_callbacks").select("id", { count: "exact", head: true }).eq("target_id", targetId),
    supa.from("exploit_runs").select("id", { count: "exact", head: true }).eq("target_id", targetId),
  ]);

  const assertions = {
    endpoints_ge_5: { pass: (epCount ?? 0) >= 5, actual: epCount ?? 0 },
    findings_ge_1: { pass: (findCount ?? 0) >= 1, actual: findCount ?? 0 },
    exploited_ge_1: { pass: (exploitedCount ?? 0) >= 1, actual: exploitedCount ?? 0 },
    oob_callbacks_ge_1: { pass: (oobCount ?? 0) >= 1, actual: oobCount ?? 0 },
    exploit_runs_ge_1: { pass: (exploitRuns ?? 0) >= 1, actual: exploitRuns ?? 0 },
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
    message: allPass ? `✅ E2E SelfTest passed all 5 assertions` : `❌ E2E SelfTest failed — see prior errors`,
    metadata: { assertions, reconR: reconR.data, fuzzR: fuzzR.data },
  });

  return new Response(JSON.stringify({ ok: true, allPass, assertions, targetId, testUrl }), {
    headers: { ...corsHeaders, "Content-Type": "application/json" }, status: 200,
  });
});
