// graphql-attack — Introspection abuse, batching DoS, alias overloading,
// field suggestion leakage, mutation IDOR.
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

interface GqlInput { targetId: string; endpoint: string; authHeader?: string; }

const INTROSPECTION = `query{__schema{types{name fields{name}}}}`;
const SUGGESTION_PROBE = `query{usrr{id}}`; // typo → "Did you mean user?"
const ALIAS_OVERLOAD = `query{${Array.from({length: 100}, (_,i)=>`a${i}:__typename`).join(" ")}}`;
const BATCH_PROBE = JSON.stringify(Array.from({length: 50}, () => ({ query: "{__typename}" })));

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  const supa = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
  let input: GqlInput;
  try { input = await req.json(); } catch { return j({ ok: false, error: "invalid json" }); }
  if (!input.endpoint) return j({ ok: false, error: "endpoint required" });

  const findings: any[] = [];
  const headers: Record<string,string> = { "Content-Type": "application/json" };
  if (input.authHeader) headers["Authorization"] = input.authHeader;

  // 1. Introspection
  try {
    const r = await safeFetch(input.endpoint, { method: "POST", headers, body: JSON.stringify({ query: INTROSPECTION }) }, 8000);
    const body = await readBodySafe(r, 12000);
    if (/"__schema"\s*:\s*\{|"types"\s*:\s*\[/.test(body)) {
      await maybePush(supa, input.targetId, findings, {
        kind: "graphql-introspection-enabled", severity: "medium",
        title: "GraphQL introspection enabled in production",
        url: input.endpoint, payload: INTROSPECTION,
        body, status: r.status, headers: headersToObject(r.headers),
        proofType: "introspection_schema_returned",
      });
    }
  } catch (_) {}

  // 2. Field suggestion leak
  try {
    const r = await safeFetch(input.endpoint, { method: "POST", headers, body: JSON.stringify({ query: SUGGESTION_PROBE }) }, 6000);
    const body = await readBodySafe(r, 6000);
    if (/Did you mean|did you mean/.test(body)) {
      await maybePush(supa, input.targetId, findings, {
        kind: "graphql-suggestion-leak", severity: "low",
        title: "GraphQL field suggestions leak schema names",
        url: input.endpoint, payload: SUGGESTION_PROBE,
        body, status: r.status, headers: headersToObject(r.headers),
        proofType: "did_you_mean_in_response",
      });
    }
  } catch (_) {}

  // 3. Alias overloading (DoS amplification)
  try {
    const t0 = Date.now();
    const r = await safeFetch(input.endpoint, { method: "POST", headers, body: JSON.stringify({ query: ALIAS_OVERLOAD }) }, 12000);
    const dt = Date.now() - t0;
    const body = await readBodySafe(r, 6000);
    if (r.status === 200 && (body.match(/__typename/g) || []).length >= 50 && dt > 500) {
      await maybePush(supa, input.targetId, findings, {
        kind: "graphql-alias-overload", severity: "medium",
        title: "GraphQL alias overloading allowed (DoS amplification)",
        url: input.endpoint, payload: "100 aliased __typename",
        body, status: r.status, headers: { ...headersToObject(r.headers), "x-elapsed-ms": String(dt) },
        proofType: "100_aliases_executed",
      });
    }
  } catch (_) {}

  // 4. Batching DoS
  try {
    const r = await safeFetch(input.endpoint, { method: "POST", headers, body: BATCH_PROBE }, 12000);
    const body = await readBodySafe(r, 6000);
    // Server returned a JSON array of N results → batching enabled
    try {
      const parsed = JSON.parse(body);
      if (Array.isArray(parsed) && parsed.length >= 50) {
        await maybePush(supa, input.targetId, findings, {
          kind: "graphql-batching-enabled", severity: "medium",
          title: "GraphQL request batching enabled (DoS / brute-force amplifier)",
          url: input.endpoint, payload: "50-query batch",
          body, status: r.status, headers: headersToObject(r.headers),
          proofType: "batch_array_response",
        });
      }
    } catch (_) {}
  } catch (_) {}

  return j({ ok: true, findings_count: findings.length, findings });
});

async function maybePush(supa: any, targetId: string, out: any[], f: any) {
  const verdict = await confirmFinding({
    vulnClass: f.kind, payload: f.payload, endpoint: f.url,
    mutated: { status: f.status, bodySnippet: f.body.slice(0,1500), length: f.body.length, headers: f.headers },
    deterministicProof: true, proofType: f.proofType,
  });
  if (verdict.recommendedAction === "drop_false_positive" || verdict.recommendedAction === "drop_honeypot") return;
  const isApproval = verdict.recommendedAction === "insert_approval";
  const table = isApproval ? "pending_approvals" : "vulnerability_findings";
  const row = isApproval
    ? { target_id: targetId, finding_type: f.kind, severity: f.severity, title: f.title,
        description: verdict.reasoning, payload_used: f.payload,
        confidence_score: verdict.confidence, ai_verified: true, ai_verification_notes: verdict.reasoning,
        evidence: { url: f.url, status: f.status, body_snippet: f.body.slice(0,2000), proofType: f.proofType } }
    : { target_id: targetId, title: f.title, severity: f.severity,
        description: verdict.reasoning, payload: f.payload,
        confidence_score: verdict.confidence, ai_verified: true,
        triage_reasoning: verdict.reasoning, validation_status: "verified" };
  const { data } = await supa.from(table).insert(row).select("id").single();
  out.push({ id: data?.id, kind: f.kind, severity: f.severity, title: f.title });
}
function j(b: unknown, s = 200) { return new Response(JSON.stringify(b), { status: s, headers: { ...corsHeaders, "Content-Type": "application/json" } }); }
