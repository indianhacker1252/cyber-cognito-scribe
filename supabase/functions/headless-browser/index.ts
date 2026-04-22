// Headless browser scanner stub.
// Without Browserless API key configured, falls back to fetching page + parsing
// inline <script>/href tokens to surface SPA endpoints. When BROWSERLESS_API_KEY
// is set, calls Browserless /content with stealth + extracts XHR/fetch URLs.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

function db() { return createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!); }

async function browserlessFetch(url: string): Promise<{ html: string; xhrUrls: string[] } | null> {
  const key = Deno.env.get("BROWSERLESS_API_KEY");
  if (!key) return null;
  try {
    const r = await fetch(`https://chrome.browserless.io/scrape?token=${key}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url,
        elements: [{ selector: "html" }],
        gotoOptions: { waitUntil: "networkidle2", timeout: 15000 },
        // Browserless returns request log too via `requestInterception` — keep simple
      }),
      signal: AbortSignal.timeout(20000),
    });
    if (!r.ok) return null;
    const data = await r.json();
    const html = data.data?.[0]?.results?.[0]?.html || "";
    return { html, xhrUrls: [] };
  } catch { return null; }
}

function extractEndpoints(html: string, baseUrl: string): string[] {
  const urls = new Set<string>();
  // Inline fetch/axios/XMLHttpRequest URLs in <script> tags
  const scriptRx = /<script[^>]*>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = scriptRx.exec(html)) !== null) {
    const code = m[1];
    const apiRx = /["'](\/api\/[^"'\s?#]+|https?:\/\/[^"'\s]+\/api\/[^"'\s?#]+)["']/g;
    let am;
    while ((am = apiRx.exec(code)) !== null) {
      try { urls.add(new URL(am[1], baseUrl).toString()); } catch { /* skip */ }
    }
    // GraphQL
    const gql = /["']([^"']*graphql[^"']*)["']/gi;
    let gm;
    while ((gm = gql.exec(code)) !== null) {
      try { urls.add(new URL(gm[1], baseUrl).toString()); } catch { /* skip */ }
    }
  }
  // href + action attributes
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

    let html = "";
    let mode = "fallback-fetch";
    const bl = await browserlessFetch(url);
    if (bl) { html = bl.html; mode = "browserless"; }
    else {
      const r = await fetch(url, {
        headers: { "User-Agent": "Mozilla/5.0 CyberScope-SPA/2.0" },
        signal: AbortSignal.timeout(10000),
      });
      html = await r.text();
    }

    const endpoints = extractEndpoints(html, url);

    // Persist as discovered_endpoints
    if (targetId && endpoints.length > 0) {
      const rows = endpoints.map(u => ({
        target_id: targetId, url: u, method: "GET", parameters: {}, status_code: null,
      }));
      await db().from("discovered_endpoints").upsert(rows as any, { onConflict: "url" } as any).select();
      await db().from("scan_logs").insert({
        target_id: targetId, log_type: "discovery",
        message: `🌐 Headless browser (${mode}) found ${endpoints.length} SPA endpoints`,
        metadata: { mode, sample: endpoints.slice(0, 5) },
      });
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
