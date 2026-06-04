// Proof Engine — promotes a finding's proof_tier from signal → reflected → exploited
// based on hard artifacts. Streams live progress to scan_logs (Neural Log).
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { safeFetch } from "../_shared/safe-fetch.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};
const db = () => createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

const SENSITIVE_PATTERNS = [
  /root:x:0:0:/i, /-----BEGIN (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----/i,
  /aws_secret_access_key/i, /AKIA[0-9A-Z]{16}/, /xox[baprs]-[0-9A-Za-z-]+/,
  /ghp_[A-Za-z0-9]{36}/, /eyJ[A-Za-z0-9_=-]+\.eyJ[A-Za-z0-9_=-]+\.[A-Za-z0-9_.+/=-]+/,
  /Authorization:\s*Bearer\s+[A-Za-z0-9._-]+/i, /password\s*[:=]\s*["'][^"']{6,}/i,
];

async function log(supa: any, target_id: string | null, log_type: string, message: string, metadata: any = {}) {
  try { await supa.from("scan_logs").insert({ target_id, log_type, message, metadata }); } catch {}
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const { findingId } = await req.json();
    if (!findingId) {
      return new Response(JSON.stringify({ ok: false, error: "findingId required" }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    const supa = db();
    const { data: f } = await supa.from("vulnerability_findings").select("*").eq("id", findingId).maybeSingle();
    if (!f) return new Response(JSON.stringify({ ok: false, error: "not found" }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });

    await log(supa, f.target_id, "thought", `🔬 Proof Engine started for "${f.title}" (current tier: ${f.proof_tier || "signal"})`, { findingId });

    let tier: "signal" | "reflected" | "exploited" = "signal";
    let sensitive = false;
    const artifacts: any = {};

    // 1. OOB callbacks
    await log(supa, f.target_id, "action", `→ Stage 1/4: scanning OOB callbacks (DNS/HTTP beacons)…`);
    const { data: oob } = await supa.from("oob_callbacks")
      .select("id,token,callback_type,received_at,source_ip")
      .or(`finding_id.eq.${findingId},target_id.eq.${f.target_id}`)
      .not("received_at", "is", null)
      .order("received_at", { ascending: false }).limit(3);
    if (oob && oob.length) {
      tier = "exploited"; artifacts.oob = oob;
      await log(supa, f.target_id, "result", `✅ OOB CONFIRMED — ${oob.length} callback(s) received from ${oob[0].source_ip || "unknown"}`, { oob });
    } else {
      await log(supa, f.target_id, "info", `   no OOB callbacks bound to this finding`);
    }

    // 2. Sandbox executions
    await log(supa, f.target_id, "action", `→ Stage 2/4: checking sandbox execution evidence…`);
    const { data: sbx } = await supa.from("sandbox_executions")
      .select("id,proven,output,executor")
      .eq("finding_id", findingId).eq("proven", true).limit(3);
    if (sbx && sbx.length) {
      tier = "exploited"; artifacts.sandbox = sbx.map(s => ({ id: s.id, executor: s.executor }));
      await log(supa, f.target_id, "result", `✅ SANDBOX PROVEN — ${sbx.length} run(s) flagged proven by ${sbx[0].executor}`, { sandbox: artifacts.sandbox });
      for (const s of sbx) {
        if (s.output && SENSITIVE_PATTERNS.some(p => p.test(s.output))) {
          sensitive = true; artifacts.exfil = true;
          await log(supa, f.target_id, "error", `🚨 SENSITIVE DATA EXFIL DETECTED — finding flagged sensitive (admin-only)`, {});
          break;
        }
      }
    } else {
      await log(supa, f.target_id, "info", `   no proven sandbox runs yet`);
    }

    // 3. Probe reflection
    await log(supa, f.target_id, "action", `→ Stage 3/4: live probe reflection test…`);
    if (tier === "signal" && f.poc) {
      const m = f.poc.match(/(https?:\/\/[^\s"']+)/);
      if (m) {
        const probe = `cs_proof_${Math.random().toString(36).slice(2,8)}`;
        const url = new URL(m[1]);
        url.searchParams.set("__cs", probe);
        const r = await safeFetch(url.toString(), { method: "GET", timeoutMs: 12000 });
        if (r) {
          const txt = (await r.text().catch(() => "")) || "";
          if (txt.includes(probe)) {
            tier = "reflected"; artifacts.reflected = { probe, status: r.status };
            await log(supa, f.target_id, "result", `✅ Probe "${probe}" reflected (status ${r.status}) → tier=reflected`);
          } else {
            await log(supa, f.target_id, "info", `   probe not reflected (status ${r.status}, ${txt.length}b)`);
          }
          if (SENSITIVE_PATTERNS.some(p => p.test(txt))) {
            sensitive = true; tier = "exploited";
            await log(supa, f.target_id, "error", `🚨 Sensitive pattern in live response — tier promoted to exploited`);
          }
        } else {
          await log(supa, f.target_id, "warning", `   probe fetch failed (network/timeout)`);
        }
      }
    } else if (tier === "exploited") {
      await log(supa, f.target_id, "info", `   skipped (already exploited)`);
    }

    // 4. Persist
    await log(supa, f.target_id, "action", `→ Stage 4/4: persisting proof tier = ${tier}, sensitive=${sensitive}`);
    await supa.from("vulnerability_findings").update({
      proof_tier: tier, sensitive, hard_evidence: artifacts,
      validation_status: tier === "exploited" ? "validated" : f.validation_status,
    } as any).eq("id", findingId);

    await log(supa, f.target_id, tier === "exploited" ? "result" : "info",
      `🏁 Proof Engine done — tier=${tier} sensitive=${sensitive}`, { findingId, tier, sensitive });

    return new Response(JSON.stringify({ ok: true, proof_tier: tier, sensitive, artifacts }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: e instanceof Error ? e.message : "err" }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
