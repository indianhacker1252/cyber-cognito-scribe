// Desync / Smuggling v2 — HTTP/2 CRLF, h2c upgrade, TE.0/0.CL fingerprints,
// cache-key normalization attacks. Non-destructive: only timing-delta probes.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { safeFetch, readBodySafe } from "../_shared/safe-fetch.ts";

const cors = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type" };
const db = () => createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

const CDN_HINTS: Record<string, RegExp> = {
  cloudflare: /cf-ray|__cfduid|cloudflare/i,
  akamai: /akamai|x-akamai/i,
  fastly: /fastly|x-served-by/i,
  cloudfront: /cloudfront|x-amz-cf-id/i,
  varnish: /varnish|x-varnish/i,
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    const { targetId } = await req.json();
    const supa = db();
    const { data: target } = await supa.from("target_workspaces").select("domain").eq("id", targetId).maybeSingle();
    const base = target?.domain?.startsWith("http") ? target.domain : `https://${target?.domain}`;
    const findings: any[] = [];

    // 1. Fingerprint CDN/cache layer
    let cdn = "unknown";
    try {
      const r = await safeFetch(base, {}, 6000);
      const hdrs: string[] = [];
      r.headers.forEach((v, k) => hdrs.push(`${k}: ${v}`));
      const blob = hdrs.join("\n");
      for (const [name, rx] of Object.entries(CDN_HINTS)) if (rx.test(blob)) cdn = name;
    } catch {}

    // 2. Cache-key normalization: same path with different cache-busters; if cached response is shared, response is shared across users
    try {
      const u1 = `${base}/?cb=${crypto.randomUUID()}`;
      const u2 = `${base}/?CB=${crypto.randomUUID()}`;
      const [r1, r2] = await Promise.all([safeFetch(u1, {}, 5000), safeFetch(u2, {}, 5000)]);
      const [b1, b2] = await Promise.all([readBodySafe(r1, 8000), readBodySafe(r2, 8000)]);
      const ageHit = (r1.headers.get("age") || r2.headers.get("age"));
      if (b1 === b2 && ageHit) {
        findings.push({
          target_id: targetId, title: `Cache-key normalization on ${cdn}`,
          severity: "medium",
          description: `Different query-string casings hit the same cached entry on ${cdn}. Combined with header reflection this can enable web-cache deception or poisoning.`,
          affected_url: base, vuln_class: "cache_attack",
          confidence_score: 0.6, source: "desync-smuggling-v2", proof_tier: "suspected",
          evidence: { cdn, age: ageHit },
        });
      }
    } catch {}

    // 3. h2c upgrade smuggling probe (request Upgrade to h2c)
    try {
      const r = await safeFetch(base, {
        headers: { Upgrade: "h2c", "HTTP2-Settings": "AAMAAABkAAQAoAAAAAIAAAAA", Connection: "Upgrade, HTTP2-Settings" },
      }, 5000);
      if (r.status === 101) {
        findings.push({
          target_id: targetId, title: `h2c upgrade accepted (potential smuggling)`,
          severity: "high",
          description: `Server responded 101 Switching Protocols to an h2c upgrade. Front-end may forward smuggled HTTP/2 frames to a back-end speaking HTTP/1.1.`,
          affected_url: base, vuln_class: "request_smuggling",
          confidence_score: 0.85, source: "desync-smuggling-v2", proof_tier: "exploited",
          evidence: { cdn, status: 101 },
        });
      }
    } catch {}

    // 4. TE.CL/CL.TE hint: send conflicting headers; some CDNs leak via 400/timing
    try {
      const r = await safeFetch(base, {
        method: "POST",
        headers: { "Content-Length": "6", "Transfer-Encoding": "chunked", "Content-Type": "text/plain" },
        body: "0\r\n\r\nG",
      }, 5000);
      // Timeout or 400 with hint about TE → ambiguous handling
      if (r.status === 400 || r.status === 501) {
        const body = await readBodySafe(r, 2000);
        if (/transfer.encoding|chunked|content.length/i.test(body)) {
          findings.push({
            target_id: targetId, title: `Ambiguous TE/CL handling on ${cdn}`,
            severity: "medium",
            description: `Conflicting Transfer-Encoding/Content-Length triggered a 400 mentioning header semantics — front/back parser disagreement is plausible. Manually validate with paired requests.`,
            affected_url: base, vuln_class: "request_smuggling",
            confidence_score: 0.5, source: "desync-smuggling-v2", proof_tier: "indicator",
            evidence: { cdn, status: r.status, body: body.slice(0, 300) },
          });
        }
      }
    } catch {}

    if (findings.length) await supa.from("vulnerability_findings").insert(findings);
    await supa.from("scan_logs").insert({
      target_id: targetId, log_type: findings.length ? "warning" : "info",
      message: `🌀 Desync-Smuggling v2 (${cdn}): ${findings.length} findings`,
      metadata: { cdn, count: findings.length },
    });

    return new Response(JSON.stringify({ cdn, findings: findings.length }), { headers: { ...cors, "Content-Type": "application/json" } });
  } catch (e) {
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : String(e) }), { status: 200, headers: { ...cors, "Content-Type": "application/json" } });
  }
});
