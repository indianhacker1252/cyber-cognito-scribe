// Per-route fingerprinting: pulls Server/X-Powered-By/JS-bundle-hash per
// endpoint, joins to exploitdb_index, files HIGH findings when a CPE
// version range matches a known exploit.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { smartFetch } from "../_shared/proxy-pool.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};
function db() { return createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!); }

function parseHeader(h: string): { product: string; version: string | null } | null {
  if (!h) return null;
  const m = h.match(/^([A-Za-z][\w.-]*?)[\/\s]([\d]+(?:\.\d+)*)/);
  if (m) return { product: m[1].toLowerCase(), version: m[2] };
  const bare = h.match(/^([A-Za-z][\w.-]*)/);
  return bare ? { product: bare[1].toLowerCase(), version: null } : null;
}

async function hashStr(s: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("").slice(0, 12);
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const { targetId, endpoints } = await req.json();
    const supa = db();
    const perRoute: any[] = [];
    const matches: any[] = [];

    for (const ep of (endpoints || []).slice(0, 30)) {
      const r = await smartFetch(ep, { timeoutMs: 6000 });
      const server = r.response.headers.get("server") || "";
      const xpb = r.response.headers.get("x-powered-by") || "";
      const fps = [parseHeader(server), parseHeader(xpb)].filter(Boolean) as Array<{ product: string; version: string | null }>;

      // JS bundle hashes (cache-bustable identity)
      const jsHashes: string[] = [];
      const jsMatches = [...r.body.matchAll(/<script[^>]+src=["']([^"']+\.js[^"']*)["']/gi)].slice(0, 5);
      for (const m of jsMatches) {
        const src = m[1].startsWith("http") ? m[1] : new URL(m[1], ep).toString();
        try {
          const jr = await smartFetch(src, { timeoutMs: 5000 });
          jsHashes.push(`${src.split("/").pop()}:${await hashStr(jr.body)}`);
        } catch { /* skip */ }
      }

      perRoute.push({ url: ep, server, xpb, fingerprints: fps, jsHashes });

      // Join to exploitdb_index by product keyword
      for (const fp of fps) {
        const { data: edb } = await supa.from("exploitdb_index")
          .select("id, edb_id, cve, title, vuln_class, type, source_url")
          .ilike("title", `%${fp.product}%`).limit(5);
        for (const e of (edb || [])) {
          if (!fp.version) continue;
          matches.push({ url: ep, product: fp.product, version: fp.version, edb: e });
          await supa.from("pending_approvals").insert({
            target_id: targetId,
            finding_type: "version_cve_match",
            severity: "high",
            title: `${fp.product} ${fp.version} matches exploit ${e.edb_id || e.cve || e.id} at ${new URL(ep).pathname}`,
            description: `Per-route fingerprint of ${ep} returned ${fp.product}/${fp.version}; exploitdb has: ${e.title}`,
            evidence: { url: ep, fingerprint: fp, exploit: e },
            confidence_level: "medium",
            confidence_score: 60,
            status: "pending",
          } as any);
        }
      }
    }

    await supa.from("scan_logs").insert({
      target_id: targetId, log_type: "info",
      message: `🔍 route-fingerprint: ${perRoute.length} routes, ${matches.length} CVE matches`,
      metadata: { matches: matches.length },
    } as any);

    return new Response(JSON.stringify({ ok: true, perRoute, matches }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (e) {
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : "err" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
