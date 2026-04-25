// Headless browser scanner — supports two backends, configured via
// external_infra_config (service='browserless'):
//   1. cloud      → uses Browserless cloud (BROWSERLESS_API_KEY env or token in config)
//   2. self_hosted→ user-run Browserless/Playwright server on their host
// Falls back to plain HTTP fetch + script/href regex extraction when neither is configured.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

function db() { return createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!); }

interface BrowserConfig {
  mode: "cloud" | "self_hosted" | "disabled";
  endpoint_url?: string | null;
  auth_token?: string | null;
}

async function loadConfig(): Promise<BrowserConfig> {
  const { data } = await db().from("external_infra_config")
    .select("*").eq("service", "browserless").eq("is_active", true).maybeSingle();
  if (data) {
    return {
      mode: ((data as any).mode as BrowserConfig["mode"]) || "cloud",
      endpoint_url: (data as any).endpoint_url,
      auth_token: (data as any).auth_token,
    };
  }
  // Fallback to env BROWSERLESS_API_KEY
  if (Deno.env.get("BROWSERLESS_API_KEY")) {
    return { mode: "cloud", endpoint_url: "https://chrome.browserless.io",
      auth_token: Deno.env.get("BROWSERLESS_API_KEY") };
  }
  return { mode: "disabled" };
}

async function browserlessScrape(cfg: BrowserConfig, url: string): Promise<{ html: string; xhr: string[] } | null> {
  if (cfg.mode === "disabled") return null;
  const base = (cfg.endpoint_url || "https://chrome.browserless.io").replace(/\/$/, "");
  const tokenQS = cfg.auth_token ? `?token=${encodeURIComponent(cfg.auth_token)}` : "";
  try {
    // /scrape endpoint returns html via element selectors
    const r = await fetch(`${base}/scrape${tokenQS}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url,
        elements: [{ selector: "html" }],
        gotoOptions: { waitUntil: "networkidle2", timeout: 15000 },
        rejectResourceTypes: ["image", "media", "font"],
      }),
      signal: AbortSignal.timeout(20000),
    });
    if (!r.ok) return null;
    const data = await r.json();
    const html = data.data?.[0]?.results?.[0]?.html || "";
    return { html, xhr: [] };
  } catch { return null; }
}

function extractEndpoints(html: string, baseUrl: string): string[] {
  const urls = new Set<string>();
  const scriptRx = /<script[^>]*>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = scriptRx.exec(html)) !== null) {
    const code = m[1];
    const apiRx = /["'](\/api\/[^"'\s?#]+|https?:\/\/[^"'\s]+\/api\/[^"'\s?#]+)["']/g;
    let am;
    while ((am = apiRx.exec(code)) !== null) {
      try { urls.add(new URL(am[1], baseUrl).toString()); } catch { /* skip */ }
    }
    const gql = /["']([^"']*graphql[^"']*)["']/gi;
    let gm;
    while ((gm = gql.exec(code)) !== null) {
      try { urls.add(new URL(gm[1], baseUrl).toString()); } catch { /* skip */ }
    }
  }
  const attrRx = /(?:href|action)\s*=\s*["']([^"']+)["']/gi;
  while ((m = attrRx.exec(html)) !== null) {
    try {
      const u = new URL(m[1], baseUrl);
      if (u.search || /\.(php|aspx|jsp|json|xml)$/i.test(u.pathname)) urls.add(u.toString());
    } catch { /* skip */ }
  }
  return [...urls].slice(0, 40);
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const { targetId, url } = await req.json();
    if (!url) return new Response(JSON.stringify({ error: "url required" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });

    const cfg = await loadConfig();
    let html = "", mode = "fallback-fetch";
    const bl = await browserlessScrape(cfg, url);
    if (bl) { html = bl.html; mode = `browserless:${cfg.mode}`; }
    else {
      const r = await fetch(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 CyberScope-SPA/2.0" },
        signal: AbortSignal.timeout(10000),
      });
      html = await r.text();
    }

    const endpoints = extractEndpoints(html, url);

    if (targetId && endpoints.length > 0) {
      const rows = endpoints.map(u => ({
        target_id: targetId, url: u, method: "GET", parameters: {}, status_code: null,
      }));
      await db().from("discovered_endpoints").upsert(rows as any, { onConflict: "url" } as any).select();
      await db().from("scan_logs").insert({
        target_id: targetId, log_type: "info",
        message: `🌐 Headless browser (${mode}) found ${endpoints.length} SPA endpoints`,
        metadata: { mode, sample: endpoints.slice(0, 5) },
      } as any);
    }

    return new Response(JSON.stringify({ mode, endpoints, htmlLength: html.length }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (e) {
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : "err" }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
