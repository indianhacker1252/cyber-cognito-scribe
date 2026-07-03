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

function db() {
  return createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
}

interface BrowserConfig {
  mode: "cloud" | "self_hosted" | "disabled";
  endpoint_url?: string | null;
  auth_token?: string | null;
}

async function loadConfig(): Promise<BrowserConfig> {
  const { data } = await db()
    .from("external_infra_config")
    .select("*")
    .eq("service", "browserless")
    .eq("is_active", true)
    .maybeSingle();
  if (data) {
    return {
      mode: ((data as any).mode as BrowserConfig["mode"]) || "cloud",
      endpoint_url: (data as any).endpoint_url,
      auth_token: (data as any).auth_token,
    };
  }
  // Fallback to env BROWSERLESS_API_KEY
  if (Deno.env.get("BROWSERLESS_API_KEY")) {
    return {
      mode: "cloud",
      endpoint_url: "https://chrome.browserless.io",
      auth_token: Deno.env.get("BROWSERLESS_API_KEY"),
    };
  }
  return { mode: "disabled" };
}
// When browserless is disabled, use a smarter static extraction fallback
// that handles React SPAs by analyzing bundle JS files:

async function spaFallbackExtraction(url: string): Promise<{ endpoints: string[]; forms: any[] }> {
  const endpoints = new Set<string>();
  const forms: any[] = [];

  try {
    // Fetch the main HTML
    const r = await fetch(url, { headers: { "User-Agent": "Mozilla/5.0" }, signal: AbortSignal.timeout(10000) });
    const html = await r.text();

    // Extract JS bundle URLs
    const jsBundles = [...html.matchAll(/src=["']([^"']+\.js[^"']*)['"]/gi)]
      .map((m) => {
        try {
          return new URL(m[1], url).toString();
        } catch {
          return null;
        }
      })
      .filter(Boolean) as string[];

    // Fetch and analyze each JS bundle for API routes
    await Promise.allSettled(
      jsBundles.slice(0, 5).map(async (bundleUrl) => {
        try {
          const br = await fetch(bundleUrl!, { signal: AbortSignal.timeout(8000) });
          const code = await br.text();

          // Extract API paths from React Router / Next.js patterns
          const apiPaths = [
            ...code.matchAll(/["'](\/api\/[^"'\s,)]{2,60})["']/g),
            ...code.matchAll(/path:\s*["'](\/[^"'\s,)]{2,60})["']/g),
            ...code.matchAll(/route\(['"](\/[^'"]+)['"]/g),
            ...code.matchAll(/axios\.(get|post|put|delete)\(['"](\/[^'"]+)['"]/g),
            ...code.matchAll(/fetch\(['"](\/[^'"]+)['"]/g),
          ];

          for (const m of apiPaths) {
            const path = m[m.length - 1]; // last capture group = the path
            if (path && path.length > 1 && !path.includes("*")) {
              try {
                endpoints.add(new URL(path, url).toString());
              } catch {
                /* skip */
              }
            }
          }

          // Extract form-like patterns (login, checkout etc.)
          const formPaths = [...code.matchAll(/["'](\/(?:login|signup|checkout|account|register|auth)[^"']*)['"]/gi)];
          for (const m of formPaths) {
            try {
              const ep = new URL(m[1], url).toString();
              endpoints.add(ep);
              forms.push({ action: ep, method: "POST", inputs: ["email", "password", "username"] });
            } catch {
              /* skip */
            }
          }
        } catch {
          /* skip bundle */
        }
      }),
    );
  } catch {
    /* skip */
  }

  return { endpoints: [...endpoints].slice(0, 50), forms };
}
async function browserlessScrape(
  cfg: BrowserConfig,
  url: string,
): Promise<{ html: string; xhr: string[]; spaEndpoints?: string[]; spaForms?: any[] } | null> {
  if (cfg.mode === "disabled") {
    // Don't give up — use SPA fallback extraction (parses JS bundles for
    // API routes) AND fetch the raw HTML so the caller's extractEndpoints()
    // regex pass still has something to work with. Previously this branch
    // returned a Response object where {html, xhr} was expected — bl.html
    // and bl.xhr were always undefined, so extractEndpoints ran on an empty
    // string and every SPA scan logged "0 URLs, 0 forms" regardless of how
    // good spaFallbackExtraction's own logic was.
    const fallback = await spaFallbackExtraction(url);
    let rawHtml = "";
    try {
      const r = await fetch(url, { headers: { "User-Agent": "Mozilla/5.0" }, signal: AbortSignal.timeout(8000) });
      rawHtml = await r.text();
    } catch {
      /* keep going with empty html — spaEndpoints still has value */
    }
    return { html: rawHtml, xhr: [], spaEndpoints: fallback.endpoints, spaForms: fallback.forms };
  }
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
  } catch {
    return null;
  }
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
      try {
        urls.add(new URL(am[1], baseUrl).toString());
      } catch {
        /* skip */
      }
    }
    const gql = /["']([^"']*graphql[^"']*)["']/gi;
    let gm;
    while ((gm = gql.exec(code)) !== null) {
      try {
        urls.add(new URL(gm[1], baseUrl).toString());
      } catch {
        /* skip */
      }
    }
  }
  const attrRx = /(?:href|action)\s*=\s*["']([^"']+)["']/gi;
  while ((m = attrRx.exec(html)) !== null) {
    try {
      const u = new URL(m[1], baseUrl);
      if (u.search || /\.(php|aspx|jsp|json|xml)$/i.test(u.pathname)) urls.add(u.toString());
    } catch {
      /* skip */
    }
  }
  return [...urls].slice(0, 40);
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const { targetId, url } = await req.json();
    if (!url)
      return new Response(JSON.stringify({ error: "url required" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });

    const cfg = await loadConfig();
    let html = "",
      mode = "fallback-fetch";
    const bl = await browserlessScrape(cfg, url);
    let spaEndpoints: string[] = [];
    let spaForms: any[] = [];
    if (bl) {
      html = bl.html;
      mode = `browserless:${cfg.mode}`;
      spaEndpoints = bl.spaEndpoints || [];
      spaForms = bl.spaForms || [];
    } else {
      const r = await fetch(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 CyberScope-SPA/2.0" },
        signal: AbortSignal.timeout(10000),
      });
      html = await r.text();
    }

    // Merge regex-extracted endpoints with JS-bundle-parsed SPA endpoints —
    // the two methods catch different things (regex catches static hrefs,
    // JS-bundle parsing catches React Router / axios / fetch() calls that
    // never appear as literal HTML).
    const regexEndpoints = extractEndpoints(html, url);
    const endpoints = [...new Set([...regexEndpoints, ...spaEndpoints])];

    if (targetId && endpoints.length > 0) {
      const rows = endpoints.map((u) => ({
        target_id: targetId,
        url: u,
        method: "GET",
        parameters: {},
        status_code: null,
      }));
      await db()
        .from("discovered_endpoints")
        .upsert(rows as any, { onConflict: "url" } as any)
        .select();
      await db()
        .from("scan_logs")
        .insert({
          target_id: targetId,
          log_type: "info",
          message: `🌐 Headless browser (${mode}) found ${endpoints.length} SPA endpoints (${regexEndpoints.length} regex + ${spaEndpoints.length} JS-bundle-parsed)`,
          metadata: { mode, sample: endpoints.slice(0, 5) },
        } as any);
    }

    // Store SPA-discovered forms (login, checkout, register, etc.) so
    // form-attacker actually has data — these were previously found but
    // never persisted to discovered_forms.
    if (targetId && spaForms.length > 0) {
      const formRows = spaForms.map((f: any) => ({
        target_id: targetId,
        action_url: f.action,
        method: f.method || "POST",
        fields: (f.inputs || []).map((name: string) => ({ name, type: "text" })),
        source: "spa-fallback",
      }));
      await db()
        .from("discovered_forms")
        .upsert(formRows as any)
        .select();
    }

    return new Response(JSON.stringify({ mode, endpoints, htmlLength: html.length }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (e) {
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : "err" }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
