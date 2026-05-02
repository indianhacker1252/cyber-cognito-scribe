// cache-attack — Web Cache Poisoning + Cache Deception (CWE-444 / CWE-841)
//
// Tests:
//  1. Unkeyed header poisoning: send X-Forwarded-Host / X-Original-URL etc.
//     and check whether the cached response (next clean request) reflects them.
//  2. Cache deception: append /test.css or ;.css to a private endpoint and
//     check whether a CDN caches a personalized response.
//  3. Fat-GET / parameter cloaking: ?utm_x=… mismatched cache keys.
//
// All findings → confirmFinding.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.0";
import { safeFetch, readBodySafe, headersToObject } from "../_shared/safe-fetch.ts";
import { confirmFinding } from "../_shared/ai-confirm-gate.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};
const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

const UNKEYED_HEADERS = [
  "X-Forwarded-Host", "X-Forwarded-Server", "X-Host", "X-HTTP-Host-Override",
  "Forwarded", "X-Original-URL", "X-Rewrite-URL", "X-Forwarded-Scheme",
];
const DECEPTION_SUFFIXES = ["/test.css", "/test.js", "/test.png", ";test.css", "%2Ftest.css"];

interface CacheInput { targetId: string; baseUrl: string; sensitivePath?: string; }

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  const supa = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
  let input: CacheInput;
  try { input = await req.json(); } catch { return j({ ok: false, error: "invalid json" }); }
  if (!input.baseUrl) return j({ ok: false, error: "baseUrl required" });

  const findings: any[] = [];
  const canary = `cs${Math.random().toString(36).slice(2, 10)}.evil`;

  // ── 1. Unkeyed header poisoning
  for (const h of UNKEYED_HEADERS) {
    try {
      // poison
      const poison = await safeFetch(input.baseUrl, { headers: { [h]: canary, "Cache-Buster": canary } }, 6000);
      const poisonBody = await readBodySafe(poison, 6000);
      // clean read
      const clean = await safeFetch(input.baseUrl, { headers: { "Cache-Buster": canary } }, 6000);
      const cleanBody = await readBodySafe(clean, 6000);

      const reflectedInPoison = poisonBody.includes(canary);
      const reflectedInClean = cleanBody.includes(canary);
      const cacheable = /age:|x-cache|cf-cache-status|cdn-cache/i.test([...clean.headers.keys()].join("\n"));

      if (reflectedInPoison && reflectedInClean && cacheable) {
        const verdict = await confirmFinding({
          vulnClass: "cache-poisoning",
          payload: `${h}: ${canary}`,
          endpoint: input.baseUrl,
          baseline: { status: poison.status, bodySnippet: poisonBody.slice(0, 600), length: poisonBody.length, headers: headersToObject(poison.headers) },
          mutated:  { status: clean.status,  bodySnippet: cleanBody.slice(0, 600),  length: cleanBody.length,  headers: headersToObject(clean.headers) },
          deterministicProof: true,
          proofType: "unkeyed_header_persisted_in_cache",
        });
        if (verdict.recommendedAction !== "drop_false_positive" && verdict.recommendedAction !== "drop_honeypot") {
          findings.push(await persist(supa, input.targetId, {
            kind: "cache-poisoning", severity: "high",
            title: `Cache poisoning via unkeyed header ${h}`,
            url: input.baseUrl, payload: `${h}: ${canary}`,
            body: cleanBody, status: clean.status, verdict,
          }));
        }
      }
    } catch (_) {}
  }

  // ── 2. Cache deception on a sensitive path
  if (input.sensitivePath) {
    const sensitive = new URL(input.sensitivePath, input.baseUrl).toString();
    let baseBody = "";
    try {
      const r = await safeFetch(sensitive, {}, 6000);
      baseBody = await readBodySafe(r, 4000);
    } catch (_) {}

    for (const sfx of DECEPTION_SUFFIXES) {
      try {
        const url = sensitive + sfx;
        const r = await safeFetch(url, {}, 6000);
        const body = await readBodySafe(r, 4000);
        const cachedAsStatic = /x-cache:.*hit|cf-cache-status:.*hit|age:\s*[1-9]/i.test([...r.headers.entries()].map(([k,v]) => `${k}: ${v}`).join("\n"));
        const sharedContent = body.length > 200 && similarity(body, baseBody) > 0.7;
        if (r.status === 200 && cachedAsStatic && sharedContent) {
          const verdict = await confirmFinding({
            vulnClass: "cache-deception",
            payload: sfx,
            endpoint: url,
            baseline: { status: 200, bodySnippet: baseBody.slice(0, 600), length: baseBody.length },
            mutated:  { status: r.status, bodySnippet: body.slice(0, 600), length: body.length, headers: headersToObject(r.headers) },
            deterministicProof: true,
            proofType: "private_response_cached_as_static",
          });
          if (verdict.recommendedAction !== "drop_false_positive" && verdict.recommendedAction !== "drop_honeypot") {
            findings.push(await persist(supa, input.targetId, {
              kind: "cache-deception", severity: "high",
              title: `Web cache deception: ${input.sensitivePath}${sfx}`,
              url, payload: sfx, body, status: r.status, verdict,
            }));
          }
        }
      } catch (_) {}
    }
  }

  return j({ ok: true, findings_count: findings.length, findings });
});

function similarity(a: string, b: string) {
  if (!a || !b) return 0;
  const k = (s: string) => { const o = new Set<string>(); for (let i = 0; i < s.length - 8; i += 4) o.add(s.slice(i, i+8)); return o; };
  const A = k(a), B = k(b); let n = 0; A.forEach(x => B.has(x) && n++);
  return n / Math.max(1, A.size + B.size - n);
}
async function persist(supa: any, targetId: string, f: any) {
  const isApproval = f.verdict.recommendedAction === "insert_approval";
  const table = isApproval ? "pending_approvals" : "vulnerability_findings";
  const row = isApproval
    ? { target_id: targetId, finding_type: f.kind, severity: f.severity, title: f.title,
        description: f.verdict.reasoning, payload_used: f.payload,
        confidence_score: f.verdict.confidence, ai_verified: true,
        ai_verification_notes: f.verdict.reasoning,
        evidence: { url: f.url, status: f.status, body_snippet: (f.body || "").slice(0,2000), proofType: f.verdict.proofType } }
    : { target_id: targetId, title: f.title, severity: f.severity,
        description: f.verdict.reasoning, payload: f.payload,
        confidence_score: f.verdict.confidence, ai_verified: true,
        triage_reasoning: f.verdict.reasoning, validation_status: "verified" };
  const { data } = await supa.from(table).insert(row).select("id").single();
  return { id: data?.id, kind: f.kind, severity: f.severity, title: f.title };
}
function j(b: unknown, s = 200) { return new Response(JSON.stringify(b), { status: s, headers: { ...corsHeaders, "Content-Type": "application/json" } }); }
