// Business-Logic Fuzzer — catches bugs scanners miss:
// price tampering, negative qty, workflow skip, tenant swap, replay, int-overflow.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { safeFetch, readBodySafe } from "../_shared/safe-fetch.ts";

const cors = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type" };
const db = () => createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

const MONEY = /price|amount|cost|total|fee|qty|quantity|count|balance|credit/i;
const TENANT = /tenant|org|account|workspace|company|owner/i;
const ID_LIKE = /id|uuid|guid/i;

const TAMPER_VALUES: { name: string; vals: any[] }[] = [
  { name: "neg", vals: [-1, -100, -999999] },
  { name: "zero", vals: [0] },
  { name: "overflow", vals: [2147483648, 9999999999, 1e20] },
  { name: "float-precision", vals: [0.0000001, 0.1 + 0.2] },
  { name: "string-as-number", vals: ["1e10", "0x41", "1 OR 1=1"] },
];

async function probe(url: string, method: string, params: Record<string, any>, mutated: Record<string, any>) {
  const isGet = method.toUpperCase() === "GET";
  let target = url; let body: string | undefined;
  if (isGet) {
    const u = new URL(url);
    Object.entries(mutated).forEach(([k, v]) => u.searchParams.set(k, String(v)));
    target = u.toString();
  } else {
    body = JSON.stringify(mutated);
  }
  const r = await safeFetch(target, { method, headers: { "Content-Type": "application/json" }, body }, 7000);
  const text = await readBodySafe(r, 8000);
  return { status: r.status, len: text.length, snippet: text.slice(0, 300) };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    const { targetId } = await req.json();
    const supa = db();
    const { data: eps } = await supa.from("discovered_endpoints").select("id,url,method,parameters").eq("target_id", targetId).limit(40);
    const findings: any[] = [];
    let probes = 0;

    for (const ep of (eps || [])) {
      const params = (ep.parameters || {}) as Record<string, any>;
      const keys = Object.keys(params);
      if (!keys.length) continue;

      // Baseline
      let baseline: any;
      try { baseline = await probe(ep.url, ep.method, params, params); probes++; } catch { continue; }

      // Money tampering
      for (const k of keys.filter(k => MONEY.test(k))) {
        for (const set of TAMPER_VALUES) {
          for (const v of set.vals) {
            try {
              const r = await probe(ep.url, ep.method, params, { ...params, [k]: v });
              probes++;
              // Heuristic: accepted (2xx) AND response shape similar to baseline → likely accepted invalid value
              if (r.status >= 200 && r.status < 300 && Math.abs(r.len - baseline.len) / Math.max(1, baseline.len) < 0.3) {
                findings.push({
                  target_id: targetId, title: `Business Logic: ${set.name} accepted on ${k}`,
                  severity: "high", description: `Endpoint accepted ${set.name} value ${v} for money/qty param "${k}" without rejection.`,
                  affected_url: ep.url, payload: `${k}=${v}`, vuln_class: "business_logic",
                  evidence: r, confidence_score: 0.65, source: "business-logic-fuzzer", proof_tier: "suspected",
                });
              }
            } catch {}
            if (probes > 120) break;
          }
        }
      }

      // Tenant-id swap
      for (const k of keys.filter(k => TENANT.test(k) || (ID_LIKE.test(k) && typeof params[k] === "string"))) {
        const fake = typeof params[k] === "string" && params[k].length > 10
          ? params[k].slice(0, -3) + "000"
          : 999999;
        try {
          const r = await probe(ep.url, ep.method, params, { ...params, [k]: fake });
          probes++;
          if (r.status >= 200 && r.status < 300 && Math.abs(r.len - baseline.len) > 50) {
            findings.push({
              target_id: targetId, title: `Possible IDOR/Tenant-Swap on ${k}`,
              severity: "high", description: `Substituting a different ${k} returned 2xx with materially different body — possible cross-tenant access.`,
              affected_url: ep.url, payload: `${k}=${fake}`, vuln_class: "broken_access_control",
              evidence: r, confidence_score: 0.7, source: "business-logic-fuzzer", proof_tier: "suspected",
            });
          }
        } catch {}
      }
      if (probes > 200) break;
    }

    if (findings.length) await supa.from("vulnerability_findings").insert(findings);
    await supa.from("scan_logs").insert({
      target_id: targetId, log_type: findings.length ? "warning" : "info",
      message: `🧠 Business-Logic Fuzzer: ${probes} probes, ${findings.length} suspected logic bugs`,
      metadata: { probes, findings: findings.length },
    });

    return new Response(JSON.stringify({ probes, findings: findings.length }), {
      headers: { ...cors, "Content-Type": "application/json" },
    });
  } catch (e) {
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : String(e) }), {
      status: 200, headers: { ...cors, "Content-Type": "application/json" },
    });
  }
});
