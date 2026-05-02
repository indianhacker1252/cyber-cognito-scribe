// bac-tester — Broken Access Control test suite (OWASP A01)
//
// Tests:
//  1. Tenant boundary: auth-profile A token → resource owned by B
//  2. Mass assignment: POST/PATCH with extra fields like is_admin, role, owner_id
//  3. HTTP verb tampering: DELETE/PUT where GET is denied
//  4. Forced browsing: low-priv token → admin-only paths
//
// All findings flow through confirmFinding gate → no status-code-only verdicts.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.0";
import { safeFetch, readBodySafe, headersToObject } from "../_shared/safe-fetch.ts";
import { confirmFinding } from "../_shared/ai-confirm-gate.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

const ADMIN_PATHS = [
  "/admin", "/admin/users", "/admin/dashboard", "/api/admin", "/api/v1/admin",
  "/manage", "/manager", "/console", "/_admin", "/api/internal",
  "/api/users", "/api/v1/users",
];

const MASS_ASSIGN_FIELDS = {
  is_admin: true,
  isAdmin: true,
  role: "admin",
  is_superuser: true,
  permissions: ["*"],
  owner_id: "00000000-0000-0000-0000-000000000001",
  user_id: "00000000-0000-0000-0000-000000000001",
  email_verified: true,
  account_balance: 999999,
};

const VERB_PROBE = ["DELETE", "PUT", "PATCH", "OPTIONS", "TRACE", "CONNECT"];

interface BacInput {
  targetId: string;
  baseUrl: string;
  tokenLow?: string;          // low-privilege bearer
  tokenHigh?: string;         // higher-privilege bearer (for tenant-cross test)
  protectedResourcePath?: string; // e.g. /api/users/{id}
  authHeaderName?: string;    // default Authorization
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  const supa = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

  let input: BacInput;
  try { input = await req.json(); } catch {
    return json({ ok: false, error: "invalid json body" }, 200);
  }
  if (!input.baseUrl || !input.targetId) {
    return json({ ok: false, error: "baseUrl and targetId required" }, 200);
  }

  const findings: any[] = [];
  const authHeader = input.authHeaderName || "Authorization";
  const lowAuth = (t?: string) => (t ? { [authHeader]: t.startsWith("Bearer") ? t : `Bearer ${t}` } : {});

  // ── Test 1: Forced browsing to admin paths with low-priv (or no) token
  for (const p of ADMIN_PATHS) {
    const url = joinUrl(input.baseUrl, p);
    try {
      const r = await safeFetch(url, { headers: { ...lowAuth(input.tokenLow) } }, 6000);
      const body = await readBodySafe(r, 8000);
      // Deterministic proof: 200 + admin-shaped content (user list, role list)
      const looksAdmin =
        /\b(users?|accounts?|roles?|permissions?|admin)\b/i.test(body) &&
        /\[\s*\{|"id"\s*:|"email"\s*:|"role"\s*:/i.test(body);
      if (r.status === 200 && looksAdmin && body.length > 100) {
        const verdict = await confirmFinding({
          vulnClass: "broken-access-control",
          payload: `GET ${p} with ${input.tokenLow ? "low-priv token" : "no auth"}`,
          endpoint: url,
          baseline: undefined,
          mutated: { status: r.status, bodySnippet: body.slice(0, 1500), length: body.length, headers: headersToObject(r.headers) },
          deterministicProof: true,
          proofType: "admin_path_accessible",
        });
        if (verdict.recommendedAction !== "drop_false_positive" && verdict.recommendedAction !== "drop_honeypot") {
          findings.push(await persist(supa, input.targetId, {
            kind: "forced-browsing",
            title: `Admin path reachable without privileges: ${p}`,
            severity: "high",
            url, status: r.status, body, verdict,
            payload: `${input.tokenLow ? "low-priv" : "unauthenticated"} GET ${p}`,
          }));
        }
      }
    } catch (_) { /* ignore individual probe failure */ }
  }

  // ── Test 2: HTTP verb tampering on protected resource
  if (input.protectedResourcePath) {
    const url = joinUrl(input.baseUrl, input.protectedResourcePath);
    let baselineStatus = 0, baselineBody = "";
    try {
      const r = await safeFetch(url, { headers: lowAuth(input.tokenLow) }, 6000);
      baselineStatus = r.status; baselineBody = await readBodySafe(r, 4000);
    } catch (_) {}

    for (const verb of VERB_PROBE) {
      try {
        const r = await safeFetch(url, { method: verb, headers: lowAuth(input.tokenLow) }, 6000);
        const body = await readBodySafe(r, 4000);
        // If GET was 401/403 but verb returns 2xx → real ACL gap
        if (baselineStatus >= 400 && r.status >= 200 && r.status < 300) {
          const verdict = await confirmFinding({
            vulnClass: "verb-tampering",
            payload: `${verb} ${input.protectedResourcePath}`,
            endpoint: url,
            baseline: { status: baselineStatus, bodySnippet: baselineBody.slice(0, 600), length: baselineBody.length },
            mutated: { status: r.status, bodySnippet: body.slice(0, 600), length: body.length, headers: headersToObject(r.headers) },
            deterministicProof: true,
            proofType: "verb_acl_gap",
          });
          if (verdict.recommendedAction !== "drop_false_positive" && verdict.recommendedAction !== "drop_honeypot") {
            findings.push(await persist(supa, input.targetId, {
              kind: "verb-tampering",
              title: `HTTP verb ACL bypass: ${verb} succeeds where GET denied`,
              severity: "high", url, status: r.status, body, verdict, payload: `${verb} ${input.protectedResourcePath}`,
            }));
          }
        }
      } catch (_) {}
    }
  }

  // ── Test 3: Tenant boundary cross — low token requesting high token's resource
  if (input.tokenHigh && input.tokenLow && input.protectedResourcePath) {
    const url = joinUrl(input.baseUrl, input.protectedResourcePath);
    try {
      const high = await safeFetch(url, { headers: lowAuth(input.tokenHigh) }, 6000);
      const highBody = await readBodySafe(high, 6000);
      const low = await safeFetch(url, { headers: lowAuth(input.tokenLow) }, 6000);
      const lowBody = await readBodySafe(low, 6000);

      // If low-priv token gets the same private body as high-priv → IDOR
      if (low.status === 200 && high.status === 200 && lowBody.length > 200 &&
          similarity(lowBody, highBody) > 0.85) {
        const verdict = await confirmFinding({
          vulnClass: "idor-tenant-boundary",
          payload: `cross-tenant access to ${input.protectedResourcePath}`,
          endpoint: url,
          baseline: { status: high.status, bodySnippet: highBody.slice(0, 600), length: highBody.length },
          mutated: { status: low.status, bodySnippet: lowBody.slice(0, 600), length: lowBody.length },
          deterministicProof: true,
          proofType: "tenant_boundary_breach",
        });
        if (verdict.recommendedAction !== "drop_false_positive" && verdict.recommendedAction !== "drop_honeypot") {
          findings.push(await persist(supa, input.targetId, {
            kind: "idor",
            title: `Tenant boundary breach — low-priv token reads other tenant's resource`,
            severity: "critical", url, status: low.status, body: lowBody, verdict,
            payload: `low-priv GET ${input.protectedResourcePath}`,
          }));
        }
      }
    } catch (_) {}
  }

  // ── Test 4: Mass assignment on protected resource
  if (input.protectedResourcePath && input.tokenLow) {
    const url = joinUrl(input.baseUrl, input.protectedResourcePath);
    try {
      const before = await safeFetch(url, { headers: lowAuth(input.tokenLow) }, 6000);
      const beforeBody = await readBodySafe(before, 4000);

      const probe = await safeFetch(url, {
        method: "PATCH",
        headers: { ...lowAuth(input.tokenLow), "Content-Type": "application/json" },
        body: JSON.stringify(MASS_ASSIGN_FIELDS),
      }, 6000);
      const probeBody = await readBodySafe(probe, 4000);

      // Re-read & look for elevated fields echoed back
      const after = await safeFetch(url, { headers: lowAuth(input.tokenLow) }, 6000);
      const afterBody = await readBodySafe(after, 4000);

      const elevated = /"is_admin"\s*:\s*true|"role"\s*:\s*"admin"|"is_superuser"\s*:\s*true/i.test(afterBody);
      if (probe.status >= 200 && probe.status < 300 && elevated && !/"is_admin"\s*:\s*true/i.test(beforeBody)) {
        const verdict = await confirmFinding({
          vulnClass: "mass-assignment",
          payload: JSON.stringify(MASS_ASSIGN_FIELDS),
          endpoint: url,
          baseline: { status: before.status, bodySnippet: beforeBody.slice(0, 600), length: beforeBody.length },
          mutated:  { status: after.status,  bodySnippet: afterBody.slice(0, 600),  length: afterBody.length },
          deterministicProof: true,
          proofType: "mass_assignment_elevation",
        });
        if (verdict.recommendedAction !== "drop_false_positive" && verdict.recommendedAction !== "drop_honeypot") {
          findings.push(await persist(supa, input.targetId, {
            kind: "mass-assignment",
            title: `Mass assignment — privileged fields persisted`,
            severity: "critical", url, status: probe.status, body: probeBody, verdict,
            payload: JSON.stringify(MASS_ASSIGN_FIELDS),
          }));
        }
      }
    } catch (_) {}
  }

  return json({ ok: true, findings_count: findings.length, findings }, 200);
});

// ── helpers ──
function joinUrl(base: string, path: string) {
  return new URL(path, base.endsWith("/") ? base : base + "/").toString();
}

function similarity(a: string, b: string): number {
  if (!a || !b) return 0;
  const la = a.length, lb = b.length;
  if (Math.abs(la - lb) / Math.max(la, lb) > 0.3) return 0;
  // crude shingled jaccard
  const shingles = (s: string) => {
    const out = new Set<string>();
    for (let i = 0; i < s.length - 8; i += 4) out.add(s.slice(i, i + 8));
    return out;
  };
  const A = shingles(a), B = shingles(b);
  let inter = 0;
  A.forEach(x => B.has(x) && inter++);
  return inter / Math.max(1, A.size + B.size - inter);
}

async function persist(supa: any, targetId: string, f: any) {
  const isApproval = f.verdict.recommendedAction === "insert_approval";
  const table = isApproval ? "pending_approvals" : "vulnerability_findings";
  const row: any = isApproval
    ? {
        target_id: targetId, finding_type: f.kind, severity: f.severity, title: f.title,
        description: f.verdict.reasoning, payload_used: f.payload,
        confidence_score: f.verdict.confidence, ai_verified: true,
        ai_verification_notes: f.verdict.reasoning,
        evidence: { url: f.url, status: f.status, body_snippet: (f.body || "").slice(0, 2000), proofType: f.verdict.proofType },
      }
    : {
        target_id: targetId, title: f.title, severity: f.severity,
        description: f.verdict.reasoning, payload: f.payload,
        confidence_score: f.verdict.confidence, ai_verified: true,
        triage_reasoning: f.verdict.reasoning, validation_status: "verified",
      };
  const { data } = await supa.from(table).insert(row).select("id").single();
  return { id: data?.id, kind: f.kind, severity: f.severity, title: f.title };
}

function json(b: unknown, s = 200) {
  return new Response(JSON.stringify(b), { status: s, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}
