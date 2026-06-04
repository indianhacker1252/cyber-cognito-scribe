// Recursive JS endpoint expansion — fetches JS bundles, extracts referenced
// URLs / fetch() / axios() / route templates, dedupes by route template,
// recurses up to 3 levels. Persists discovered endpoints.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { smartFetch } from "../_shared/proxy-pool.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};
function db() { return createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!); }

const URL_PATTERNS = [
  /["'`](\/[a-zA-Z0-9_\-./{}:]+)["'`]/g,                       // "/api/users/{id}"
  /fetch\(\s*["'`]([^"'`]+)["'`]/g,
  /axios\.(?:get|post|put|delete|patch)\(\s*["'`]([^"'`]+)["'`]/g,
  /["'`](https?:\/\/[^"'`\s]+)["'`]/g,
];

const SKIP_EXT = /\.(png|jpg|jpeg|gif|svg|css|woff2?|ttf|ico|map)$/i;

function routeTemplate(u: string): string {
  // Collapse digits/UUIDs to {id}
  return u
    .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, "{id}")
    .replace(/\/\d{2,}(?=\/|$|\?)/g, "/{id}")
    .replace(/=\d{2,}/g, "={id}");
}

async function fetchJs(url: string): Promise<string> {
  try {
    const r = await smartFetch(url, { timeoutMs: 12000 });
    return r.body.slice(0, 500_000);
  } catch { return ""; }
}

function extractFromJs(text: string, baseUrl: string): string[] {
  const out = new Set<string>();
  for (const re of URL_PATTERNS) {
    for (const m of text.matchAll(re)) {
      const v = m[1];
      if (!v || v.length < 2 || v.length > 240) continue;
      if (SKIP_EXT.test(v)) continue;
      try {
        const abs = v.startsWith("http") ? v : new URL(v, baseUrl).toString();
        out.add(abs);
      } catch { /* skip */ }
    }
  }
  return [...out];
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const { targetId, seedUrl, maxDepth = 3, maxPerLevel = 40 } = await req.json();
    const supa = db();
    const seenTemplates = new Set<string>();
    const discovered: string[] = [];

    // Seed: fetch HTML, find <script src=...>
    const seedRes = await smartFetch(seedUrl, { timeoutMs: 12000 });
    const scriptSrcs = [...seedRes.body.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)]
      .map(m => m[1].startsWith("http") ? m[1] : new URL(m[1], seedUrl).toString())
      .slice(0, 10);

    let frontier: string[] = scriptSrcs;
    for (let depth = 0; depth < maxDepth && frontier.length; depth++) {
      const nextFrontier: string[] = [];
      for (const jsUrl of frontier.slice(0, maxPerLevel)) {
        const code = await fetchJs(jsUrl);
        if (!code) continue;
        const urls = extractFromJs(code, jsUrl);
        for (const u of urls) {
          const t = routeTemplate(u);
          if (seenTemplates.has(t)) continue;
          seenTemplates.add(t);
          discovered.push(u);
          // Recurse only into same-origin .js
          if (u.endsWith(".js") && new URL(u).origin === new URL(seedUrl).origin) {
            nextFrontier.push(u);
          }
        }
      }
      frontier = nextFrontier;
    }

    // Persist new endpoints
    for (const u of discovered.slice(0, 200)) {
      await supa.from("discovered_endpoints").insert({
        target_id: targetId, url: u, method: "GET",
        headers: { source: "js-deep-expand" },
      } as any).then(() => {}).catch(() => {});
    }

    await supa.from("scan_logs").insert({
      target_id: targetId, log_type: "info",
      message: `🧬 js-deep-expand: ${discovered.length} unique route templates from ${seedUrl}`,
      metadata: { count: discovered.length },
    } as any);

    return new Response(JSON.stringify({ ok: true, discovered: discovered.slice(0, 200) }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (e) {
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : "err" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
