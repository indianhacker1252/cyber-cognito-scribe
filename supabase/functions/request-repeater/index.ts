// Request Repeater — Burp-style. Re-fires arbitrary HTTP requests, diffs the
// response against a baseline, optionally runs WAF-bypass mutations on a
// "blocked" response, and saves promising mutations as new findings.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { safeFetch } from "../_shared/safe-fetch.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};
const db = () => createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

interface ReqSpec {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: string;
}

interface Body {
  findingId?: string;
  targetId?: string;
  baseline?: ReqSpec;
  request: ReqSpec;
  mutate?: boolean; // if true and response looks blocked, try WAF-bypass mutations
  label?: string;
}

const WAF_MUTATORS: Array<(s: string) => string> = [
  (s) => s.replace(/SELECT/gi, "SeLeCt").replace(/UNION/gi, "UnIoN"),
  (s) => s.replace(/ /g, "/**/"),
  (s) => encodeURIComponent(s),
  (s) => s.split("").map((c) => c.match(/[a-z0-9]/i) ? `%${c.charCodeAt(0).toString(16)}` : c).join(""),
  (s) => s.replace(/'/g, "%u0027").replace(/"/g, "%u0022"),
  (s) => `/*!50000${s}*/`,
  (s) => s.replace(/</g, "\\u003c").replace(/>/g, "\\u003e"),
];

async function fire(spec: ReqSpec): Promise<{ status: number; length: number; snippet: string; headers: Record<string, string> } | null> {
  const r = await safeFetch(spec.url, {
    method: spec.method,
    headers: spec.headers || {},
    body: spec.body,
    timeoutMs: 8000,
  });
  if (!r) return null;
  const txt = (await r.text().catch(() => "")) || "";
  const hdrs: Record<string, string> = {};
  r.headers.forEach((v, k) => { hdrs[k] = v; });
  return { status: r.status, length: txt.length, snippet: txt.slice(0, 2000), headers: hdrs };
}

function looksBlocked(res: { status: number; snippet: string }): boolean {
  if (res.status === 403 || res.status === 406 || res.status === 429 || res.status === 451) return true;
  return /cloudflare|akamai|imperva|sucuri|access denied|forbidden|waf|blocked/i.test(res.snippet);
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const supa = db();
    const auth = req.headers.get("Authorization") || "";
    const { data: ud } = await supa.auth.getUser(auth.replace(/^Bearer\s+/i, ""));
    const userId = ud?.user?.id;
    if (!userId) {
      return new Response(JSON.stringify({ ok: false, error: "auth required" }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    const body = await req.json() as Body;
    if (!body.request?.url) {
      return new Response(JSON.stringify({ ok: false, error: "request.url required" }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const baseRes = body.baseline ? await fire(body.baseline) : null;
    const mutRes = await fire(body.request);

    const attempts: any[] = [{ label: "primary", request: body.request, response: mutRes }];

    // Mutate if blocked
    if (body.mutate && mutRes && looksBlocked(mutRes)) {
      const seed = body.request.body || body.request.url;
      for (let i = 0; i < WAF_MUTATORS.length; i++) {
        const mut = WAF_MUTATORS[i];
        const mutated: ReqSpec = body.request.body
          ? { ...body.request, body: mut(seed) }
          : { ...body.request, url: body.request.url.replace(/([?&][^=]+=)([^&]+)/, (_, k, v) => `${k}${encodeURIComponent(mut(decodeURIComponent(v)))}`) };
        const r = await fire(mutated);
        attempts.push({ label: `waf-bypass-${i}`, request: mutated, response: r, bypassed: r && !looksBlocked(r) });
        if (r && !looksBlocked(r)) break;
      }
    }

    const diff = baseRes && mutRes ? {
      delta_status: mutRes.status - baseRes.status,
      delta_length: mutRes.length - baseRes.length,
      delta_pct: baseRes.length ? Math.abs(mutRes.length - baseRes.length) / baseRes.length : 0,
    } : {};

    const interesting = !!attempts.find(a => a.bypassed) ||
      (mutRes && baseRes && (mutRes.status !== baseRes.status || Math.abs(mutRes.length - baseRes.length) / Math.max(baseRes.length, 1) > 0.25));

    const { data: row } = await supa.from("request_replays").insert({
      user_id: userId, finding_id: body.findingId || null, target_id: body.targetId || null,
      label: body.label || "repeater",
      request: body.request as any, response: mutRes as any, diff: { ...diff, attempts: attempts.map(a => ({ label: a.label, status: a.response?.status, length: a.response?.length, bypassed: a.bypassed })) },
      is_interesting: !!interesting,
    }).select().single();

    if (body.targetId) {
      await supa.from("scan_logs").insert({
        target_id: body.targetId, log_type: interesting ? "result" : "info",
        message: `🔁 Repeater: ${body.request.method} ${body.request.url} → ${mutRes?.status || "fail"} (${mutRes?.length || 0}b)${interesting ? "  ★ interesting" : ""}`,
        metadata: { replayId: row?.id, attempts: attempts.length },
      });
    }

    return new Response(JSON.stringify({ ok: true, replayId: row?.id, baseline: baseRes, response: mutRes, attempts, diff, interesting }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: e instanceof Error ? e.message : "err" }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
