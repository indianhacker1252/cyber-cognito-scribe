// Authz grapher — crawls /api/* as user A, extracts UUIDs/IDs, replays
// each request as user B, diffs responses. 200-with-data on B = HIGH IDOR.
// Requires two auth_profiles for the target with profile_name = "user_a" and "user_b".
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { smartFetch } from "../_shared/proxy-pool.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

function db() { return createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!); }

function authHeaders(p: any): Record<string, string> {
  if (!p) return {};
  if (p.auth_type === "cookie" && p.cookie_header) return { Cookie: p.cookie_header };
  if (p.auth_type === "bearer" && p.bearer_token) return { Authorization: `Bearer ${p.bearer_token}` };
  return {};
}

const ID_PATTERNS = [
  /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, // UUID
  /\b\d{4,12}\b/g, // numeric IDs
];

function extractIds(text: string): string[] {
  const out = new Set<string>();
  for (const re of ID_PATTERNS) {
    const m = text.match(re);
    if (m) m.slice(0, 50).forEach(v => out.add(v));
  }
  return [...out].slice(0, 80);
}

function urlsWithIds(baseUrl: string, ids: string[]): string[] {
  // Replace numeric/UUID segments in path or ?id= style queries
  const u = new URL(baseUrl);
  const out = new Set<string>();
  for (const id of ids) {
    // path segment swap
    const parts = u.pathname.split("/");
    for (let i = 0; i < parts.length; i++) {
      if (/^[0-9a-f-]{4,}$/i.test(parts[i])) {
        const copy = [...parts]; copy[i] = id;
        const u2 = new URL(u.toString()); u2.pathname = copy.join("/");
        out.add(u2.toString());
      }
    }
    // query swap
    for (const k of u.searchParams.keys()) {
      const u2 = new URL(u.toString());
      u2.searchParams.set(k, id);
      out.add(u2.toString());
    }
  }
  return [...out].slice(0, 30);
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const { targetId, endpoints } = await req.json();
    const supa = db();

    const { data: profiles } = await supa.from("auth_profiles")
      .select("*").eq("target_id", targetId).in("profile_name", ["user_a", "user_b"]);
    const pa = (profiles || []).find((p: any) => p.profile_name === "user_a");
    const pb = (profiles || []).find((p: any) => p.profile_name === "user_b");

    if (!pa || !pb) {
      await supa.from("scan_logs").insert({
        target_id: targetId, log_type: "warning",
        message: "🕸️ authz-grapher needs auth_profiles named 'user_a' and 'user_b'",
      } as any);
      return new Response(JSON.stringify({ ok: false, error: "two auth profiles required" }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const findings: any[] = [];
    let probed = 0;

    for (const ep of (endpoints || []).slice(0, 25)) {
      // Step 1: hit as user A, harvest IDs from response
      const aRes = await smartFetch(ep, { headers: authHeaders(pa), timeoutMs: 6000 });
      if (aRes.response.status >= 400) continue;
      const ids = extractIds(aRes.body);
      if (!ids.length) continue;

      // Step 2: build pivot URLs and replay as user B
      for (const pivotUrl of urlsWithIds(ep, ids)) {
        probed++;
        if (probed > 80) break;
        const bRes = await smartFetch(pivotUrl, { headers: authHeaders(pb), timeoutMs: 6000 });
        // IDOR signal: 200 with substantive body AND body shares tokens with A's response
        if (bRes.response.status === 200 && bRes.body.length > 200) {
          // shared-token heuristic
          const aTokens = new Set(aRes.body.split(/[^\w-]+/).filter(t => t.length > 6));
          const bTokens = bRes.body.split(/[^\w-]+/).filter(t => t.length > 6);
          const overlap = bTokens.filter(t => aTokens.has(t)).length;
          if (overlap > 5) {
            findings.push({
              url: pivotUrl, overlap, bytes: bRes.body.length,
              evidence: bRes.body.slice(0, 600),
            });
            await supa.from("pending_approvals").insert({
              target_id: targetId,
              finding_type: "idor_authz",
              severity: "high",
              title: `IDOR: user B accessed user A's resource at ${new URL(pivotUrl).pathname}`,
              description: `Replayed ${pivotUrl} with user B's session; received 200 with ${overlap} shared tokens vs user A's body.`,
              evidence: { pivotUrl, overlap, bytesB: bRes.body.length, bodyPreview: bRes.body.slice(0, 400) },
              confidence_level: "high",
              confidence_score: 85,
              status: "pending",
            } as any);
          }
        }
      }
      if (probed > 80) break;
    }

    await supa.from("scan_logs").insert({
      target_id: targetId, log_type: "info",
      message: `🕸️ authz-grapher: probed ${probed}, ${findings.length} IDOR signals`,
      metadata: { findings: findings.length },
    } as any);

    return new Response(JSON.stringify({ ok: true, probed, findings }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (e) {
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : "err" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
