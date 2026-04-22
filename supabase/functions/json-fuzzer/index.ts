// Recursive JSON / GraphQL body fuzzer.
// Walks every string/number leaf in a sample JSON body, mutates it with
// SQLi/XSS/SSTI/path-traversal/cmdi payloads, and replays via POST.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

function db() { return createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!); }

const PAYLOADS: Record<string, string[]> = {
  sqli: [`'`, `'--`, `' OR '1'='1`, `'; SELECT pg_sleep(0)--`],
  xss: [`<cyberscope>`, `"><svg onload=cyberscope>`],
  ssti: [`{{7*7}}`, `\${7*7}`, `<%= 7*7 %>`],
  cmdi: [`; echo cyberscope_marker`, `| echo cyberscope_marker`],
  traversal: [`../../../etc/passwd`, `....//....//etc/passwd`],
  proto: [`__proto__`, `constructor.prototype`],
};

const ERROR_RX = /SQL syntax|SQLSTATE|ORA-\d|cyberscope_marker|<cyberscope>|root:.*:0:0|jinja2|TypeError.*prototype/i;

function* walkLeaves(obj: any, path: (string | number)[] = []): Generator<{ path: (string|number)[]; value: any }> {
  if (obj === null || typeof obj !== "object") { yield { path, value: obj }; return; }
  if (Array.isArray(obj)) { for (let i = 0; i < obj.length; i++) yield* walkLeaves(obj[i], [...path, i]); return; }
  for (const k of Object.keys(obj)) yield* walkLeaves(obj[k], [...path, k]);
}

function setAtPath(obj: any, path: (string|number)[], val: any): any {
  const clone = JSON.parse(JSON.stringify(obj));
  let cur = clone;
  for (let i = 0; i < path.length - 1; i++) cur = cur[path[i]];
  cur[path[path.length - 1]] = val;
  return clone;
}

async function loadAuth(targetId: string): Promise<Record<string,string>> {
  const { data } = await db().from("auth_profiles").select("auth_type, cookie_header, bearer_token")
    .eq("target_id", targetId).eq("is_valid", true).maybeSingle();
  if (!data) return {};
  if (data.auth_type === "cookie" && data.cookie_header) return { Cookie: data.cookie_header };
  if (data.auth_type === "bearer" && data.bearer_token) return { Authorization: `Bearer ${data.bearer_token}` };
  return {};
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const { targetId, endpoint, method, sampleBody, contentType } = await req.json();
    if (!endpoint || !sampleBody) {
      return new Response(JSON.stringify({ error: "endpoint and sampleBody required" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const supa = db();
    const auth = await loadAuth(targetId);
    const isGraphQL = /graphql/i.test(endpoint) || (typeof sampleBody === "object" && "query" in sampleBody);
    const findings: any[] = [];
    const tested: any[] = [];

    // Baseline
    const baselineResp = await fetch(endpoint, {
      method: method || "POST",
      headers: { "Content-Type": contentType || "application/json", ...auth },
      body: JSON.stringify(sampleBody), signal: AbortSignal.timeout(8000),
    });
    const baselineBody = await baselineResp.text();
    const baselineLen = baselineBody.length;

    const leaves = [...walkLeaves(sampleBody)].filter(l => typeof l.value === "string" || typeof l.value === "number").slice(0, 12);

    for (const leaf of leaves) {
      for (const [vc, payloads] of Object.entries(PAYLOADS)) {
        for (const p of payloads.slice(0, 2)) {
          const mutated = setAtPath(sampleBody, leaf.path, p);
          try {
            const r = await fetch(endpoint, {
              method: method || "POST",
              headers: { "Content-Type": contentType || "application/json", ...auth },
              body: JSON.stringify(mutated), signal: AbortSignal.timeout(7000),
            });
            const body = await r.text();
            const lenDelta = Math.abs(body.length - baselineLen);
            const errMatch = ERROR_RX.test(body) && !ERROR_RX.test(baselineBody);
            const statusFlip = r.status !== baselineResp.status;
            const interesting = errMatch || (statusFlip && lenDelta > 50);

            tested.push({
              path: leaf.path.join("."), vulnClass: vc, payload: p,
              status: r.status, lenDelta, errMatch, interesting,
            });

            if (interesting) {
              findings.push({
                path: leaf.path.join("."), vulnClass: vc, payload: p,
                evidence: errMatch ? "error-class leak in body" : `status ${baselineResp.status}→${r.status}, ${lenDelta}B delta`,
                bodyPreview: body.slice(0, 200),
                isGraphQL,
              });
              await supa.from("scan_logs").insert({
                target_id: targetId, log_type: "result",
                message: `🧬 JSON-fuzz hit: ${vc.toUpperCase()} at ${leaf.path.join(".")} (${errMatch ? "error-leak" : `Δ${lenDelta}B`})`,
                metadata: { endpoint, payload: p, status: r.status },
              });
            }
            await new Promise(r => setTimeout(r, 60));
          } catch { /* skip */ }
        }
      }
    }

    return new Response(JSON.stringify({
      targetId, endpoint, leavesFuzzed: leaves.length, testsRun: tested.length,
      findings, isGraphQL,
    }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (e) {
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : "err" }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
