// Differential Oracle — sends the same request shape to N similar endpoints and
// flags ones whose response shape diverges (catches access-control + hidden-feature bugs).
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { safeFetch, readBodySafe } from "../_shared/safe-fetch.ts";

const cors = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type" };
const db = () => createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

function pathShape(u: string) {
  try { return new URL(u).pathname.split("/").map(p => /^\d+$/.test(p) ? ":id" : /^[0-9a-f-]{8,}$/i.test(p) ? ":uuid" : p).join("/"); }
  catch { return u; }
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    const { targetId } = await req.json();
    const supa = db();
    const { data: eps } = await supa.from("discovered_endpoints").select("id,url,method,parameters").eq("target_id", targetId).limit(200);
    const groups = new Map<string, any[]>();
    for (const ep of (eps || [])) {
      const k = `${ep.method}::${pathShape(ep.url)}`;
      if (!groups.has(k)) groups.set(k, []);
      groups.get(k)!.push(ep);
    }

    const findings: any[] = [];
    for (const [k, arr] of groups) {
      if (arr.length < 3) continue; // need ≥3 siblings to compare
      // Probe each unauthenticated
      const results: { ep: any; status: number; len: number; ct: string }[] = [];
      for (const ep of arr.slice(0, 8)) {
        try {
          const r = await safeFetch(ep.url, { method: ep.method }, 6000);
          const t = await readBodySafe(r, 4000);
          results.push({ ep, status: r.status, len: t.length, ct: r.headers.get("content-type") || "" });
        } catch {}
      }
      if (results.length < 3) continue;

      // Majority shape
      const statuses = results.map(r => r.status);
      const modeStatus = statuses.sort((a, b) => statuses.filter(v => v === a).length - statuses.filter(v => v === b).length).pop();
      const avgLen = results.reduce((s, r) => s + r.len, 0) / results.length;

      for (const r of results) {
        const lenDelta = Math.abs(r.len - avgLen) / Math.max(1, avgLen);
        // Diverger: different status (e.g. 200 in a 403 group) OR materially different length
        if (r.status !== modeStatus && r.status >= 200 && r.status < 300) {
          findings.push({
            target_id: targetId, title: `Differential anomaly: ${r.ep.url}`,
            severity: "high",
            description: `Sibling endpoints in group "${k}" returned ${modeStatus}, but this one returned ${r.status}. Likely missing access-control or a hidden feature.`,
            affected_url: r.ep.url, payload: "", vuln_class: "broken_access_control",
            confidence_score: 0.7, source: "differential-oracle", proof_tier: "suspected",
            evidence: { group: k, mode_status: modeStatus, this_status: r.status, len_delta: lenDelta },
          });
        } else if (r.status === modeStatus && lenDelta > 0.6 && r.len > 200) {
          findings.push({
            target_id: targetId, title: `Differential length anomaly: ${r.ep.url}`,
            severity: "medium",
            description: `Response body is ${(lenDelta * 100).toFixed(0)}% different from siblings — possible data leak or unique exposure.`,
            affected_url: r.ep.url, payload: "", vuln_class: "information_disclosure",
            confidence_score: 0.55, source: "differential-oracle", proof_tier: "suspected",
            evidence: { group: k, len_delta: lenDelta },
          });
        }
      }
    }

    if (findings.length) await supa.from("vulnerability_findings").insert(findings);
    await supa.from("scan_logs").insert({
      target_id: targetId, log_type: findings.length ? "warning" : "info",
      message: `🔬 Differential Oracle: ${groups.size} groups, ${findings.length} divergences`,
      metadata: { groups: groups.size, count: findings.length },
    });

    return new Response(JSON.stringify({ groups: groups.size, findings: findings.length }), { headers: { ...cors, "Content-Type": "application/json" } });
  } catch (e) {
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : String(e) }), { status: 200, headers: { ...cors, "Content-Type": "application/json" } });
  }
});
