// request-mutator — auto-mutates the captured request of any HIGH/CRITICAL
// finding to discover chained / variant bugs. Wired by the orchestrator and
// also callable from the Findings UI ("Re-run mutations").
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { safeFetch, readBodySafe, headersToObject } from "../_shared/safe-fetch.ts";
import { recordFinding } from "../_shared/findings-writer.ts";
import { WafFeedback } from "../_shared/waf-detect.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

function db() { return createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!); }

interface Req { method: string; url: string; headers: Record<string,string>; body?: string }

// 8 mutation families (Part D2)
function mutate(base: Req): Array<{ name: string; req: Req }> {
  const out: Array<{ name: string; req: Req }> = [];
  const u = new URL(base.url);

  // 1. Param tamper — flip first numeric param
  for (const [k, v] of u.searchParams) {
    if (/^\d+$/.test(v)) {
      const u2 = new URL(base.url); u2.searchParams.set(k, String(+v + 1));
      out.push({ name: "param-id-enum", req: { ...base, url: u2.toString() } });
      break;
    }
  }
  // 2. Type juggle — append [] to first param
  for (const [k, v] of u.searchParams) {
    const u2 = new URL(base.url); u2.searchParams.delete(k); u2.searchParams.append(`${k}[]`, v);
    out.push({ name: "type-juggle-array", req: { ...base, url: u2.toString() } });
    break;
  }
  // 3. Verb swap GET→POST
  if (base.method === "GET") out.push({ name: "verb-swap-post", req: { ...base, method: "POST", body: u.search.slice(1), headers: { ...base.headers, "Content-Type": "application/x-www-form-urlencoded" } } });
  // 4. Header injection — X-Forwarded-For + X-Original-URL
  out.push({ name: "header-injection", req: { ...base, headers: { ...base.headers, "X-Forwarded-For": "127.0.0.1", "X-Original-URL": "/admin", "X-Rewrite-URL": "/admin" } } });
  // 5. Content-type swap to JSON
  if (base.body && base.method !== "GET") {
    try { const j = Object.fromEntries(new URLSearchParams(base.body)); out.push({ name: "content-type-json", req: { ...base, body: JSON.stringify(j), headers: { ...base.headers, "Content-Type": "application/json" } } }); } catch { /* */ }
  }
  // 6. Prototype-pollution param
  const u2 = new URL(base.url); u2.searchParams.set("__proto__[isAdmin]", "true"); u2.searchParams.set("constructor[prototype][polluted]","1");
  out.push({ name: "proto-pollute", req: { ...base, url: u2.toString() } });
  // 7. Mass-assignment admin flags
  const u3 = new URL(base.url); for (const k of ["isAdmin","role","admin","is_superuser","debug"]) u3.searchParams.set(k, "1");
  out.push({ name: "mass-assign-admin", req: { ...base, url: u3.toString() } });
  // 8. JWT alg=none if Authorization Bearer present
  const auth = base.headers["Authorization"] || base.headers["authorization"];
  if (auth?.startsWith("Bearer ")) {
    const parts = auth.slice(7).split(".");
    if (parts.length === 3) {
      const hdr = btoa(JSON.stringify({ alg: "none", typ: "JWT" })).replace(/=+$/,"");
      out.push({ name: "jwt-alg-none", req: { ...base, headers: { ...base.headers, Authorization: `Bearer ${hdr}.${parts[1]}.` } } });
    }
  }
  return out;
}

async function fireRequest(r: Req): Promise<{ status: number; body: string; len: number; headers: Record<string,string> }> {
  const resp = await safeFetch(r.url, { method: r.method, headers: r.headers, body: r.method === "GET" ? undefined : r.body }, 8000);
  const body = await readBodySafe(resp, 16384);
  return { status: resp.status, body, len: body.length, headers: headersToObject(resp.headers) };
}

function isInteresting(base: { status: number; len: number }, mut: { status: number; len: number; body: string }): { yes: boolean; reason: string; severity: "info"|"low"|"medium"|"high"|"critical" } {
  if (mut.status !== base.status) {
    if (mut.status === 200 && base.status >= 400) return { yes: true, reason: `auth bypass: ${base.status}→200`, severity: "critical" };
    if (mut.status === 500) return { yes: true, reason: `unhandled exception (${base.status}→500)`, severity: "medium" };
  }
  if (/SQL syntax|stack trace|Traceback|ORA-\d+|mysql_|pg::|PreparedStatement/i.test(mut.body)) return { yes: true, reason: "error leak in mutated response", severity: "high" };
  if (/__proto__|polluted/i.test(mut.body)) return { yes: true, reason: "prototype-pollution echo", severity: "high" };
  const delta = Math.abs(mut.len - base.len) / Math.max(base.len, 1);
  if (delta > 0.35 && mut.status === 200 && base.status === 200) return { yes: true, reason: `large response delta (${(delta*100|0)}%)`, severity: "low" };
  return { yes: false, reason: "", severity: "info" };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const body = await req.json().catch(() => ({}));
    const findingId: string | undefined = body.findingId;
    const targetId: string | undefined = body.targetId;
    if (!findingId && !targetId) return new Response(JSON.stringify({ ok: false, error: "findingId or targetId required" }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });

    const supa = db();
    // Load seed findings (HIGH/CRITICAL only when batch, single when findingId)
    let q = supa.from("vulnerability_findings").select("id,target_id,source,request_raw,response_diff");
    if (findingId) q = q.eq("id", findingId);
    else q = q.eq("target_id", targetId).in("severity", ["high","critical"]).order("created_at", { ascending: false }).limit(10);
    const { data: seeds } = await q;
    if (!seeds?.length) return new Response(JSON.stringify({ ok: true, mutated: 0, message: "no seeds" }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });

    let total = 0, confirmed = 0;
    for (const s of seeds) {
      if (!s.request_raw) continue;
      // parse raw HTTP request
      const lines = s.request_raw.split(/\r?\n/);
      const m = lines[0].match(/^(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+(\S+)/);
      if (!m) continue;
      const method = m[1]; const path = m[2];
      const headers: Record<string,string> = {}; let host = "";
      let i = 1; for (; i < lines.length && lines[i]; i++) { const hm = lines[i].match(/^([^:]+):\s*(.*)$/); if (hm) { headers[hm[1]] = hm[2]; if (hm[1].toLowerCase()==="host") host = hm[2]; } }
      const reqBody = lines.slice(i+1).join("\r\n") || undefined;
      if (!host) continue;
      const base: Req = { method, url: `https://${host}${path}`, headers, body: reqBody };

      const baseline = await fireRequest(base).catch(() => null);
      if (!baseline) continue;

      const waf = new WafFeedback(headers["server"] || "Unknown");
      for (const { name, req: mreq } of mutate(base)) {
        total++;
        const out = await fireRequest(mreq).catch(() => null);
        if (!out) continue;
        const verdict = isInteresting(baseline, out);
        waf.observe(baseline.status, out.status, baseline.len, out.len, out.body);
        if (!verdict.yes) continue;
        confirmed++;
        await recordFinding({
          targetId: s.target_id,
          source: "request-mutator",
          category: name.startsWith("proto") ? "prototype-pollution" : name.startsWith("jwt") ? "auth-confusion" : "idor",
          severity: verdict.severity,
          title: `[${name}] ${verdict.reason}`,
          description: `Mutation '${name}' of finding ${s.id} produced ${verdict.reason}. Original status=${baseline.status}, mutated status=${out.status}, delta=${out.len - baseline.len} bytes.`,
          payload: name,
          proofTier: verdict.severity === "critical" || verdict.severity === "high" ? "reflected" : "signal",
          evidence: { mutation: name, seed_finding: s.id, base_status: baseline.status, mut_status: out.status, base_len: baseline.len, mut_len: out.len },
          request: mreq,
          response: { status: out.status, headers: out.headers, body: out.body },
        });
      }
    }
    return new Response(JSON.stringify({ ok: true, seeds: seeds.length, mutated: total, confirmed }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: e instanceof Error ? e.message : "err" }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
