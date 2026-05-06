// Proof Engine — promotes a finding's proof_tier from signal → reflected → exploited
// based on hard artifacts (OOB callback, sandbox-proven RCE, data exfil, or
// reflected probe). Marks sensitive=true when exfil/RCE evidence is present.
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

    let tier: "signal" | "reflected" | "exploited" = "signal";
    let sensitive = false;
    const artifacts: any = {};

    // 1. OOB callback for this target/finding
    const { data: oob } = await supa.from("oob_callbacks")
      .select("id,token,callback_type,received_at,source_ip")
      .or(`finding_id.eq.${findingId},target_id.eq.${f.target_id}`)
      .not("received_at", "is", null)
      .order("received_at", { ascending: false }).limit(3);
    if (oob && oob.length) { tier = "exploited"; artifacts.oob = oob; }

    // 2. Sandbox executions proving exploit
    const { data: sbx } = await supa.from("sandbox_executions")
      .select("id,proven,output,executor")
      .eq("finding_id", findingId).eq("proven", true).limit(3);
    if (sbx && sbx.length) {
      tier = "exploited"; artifacts.sandbox = sbx.map(s => ({ id: s.id, executor: s.executor }));
      for (const s of sbx) {
        if (s.output && SENSITIVE_PATTERNS.some(p => p.test(s.output))) {
          sensitive = true; artifacts.exfil = true; break;
        }
      }
    }

    // 3. Probe reflection from baseline poc
    if (tier === "signal" && f.poc) {
      const m = f.poc.match(/(https?:\/\/[^\s"']+)/);
      if (m) {
        const probe = `cs_proof_${Math.random().toString(36).slice(2,8)}`;
        const url = new URL(m[1]);
        url.searchParams.set("__cs", probe);
        const r = await safeFetch(url.toString(), { method: "GET", timeoutMs: 6000 });
        if (r) {
          const txt = (await r.text().catch(() => "")) || "";
          if (txt.includes(probe)) { tier = "reflected"; artifacts.reflected = { probe, status: r.status }; }
          if (SENSITIVE_PATTERNS.some(p => p.test(txt))) { sensitive = true; tier = "exploited"; }
        }
      }
    }

    await supa.from("vulnerability_findings").update({
      proof_tier: tier,
      sensitive,
      hard_evidence: artifacts,
      validation_status: tier === "exploited" ? "validated" : f.validation_status,
    } as any).eq("id", findingId);

    return new Response(JSON.stringify({ ok: true, proof_tier: tier, sensitive, artifacts }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: e instanceof Error ? e.message : "err" }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
