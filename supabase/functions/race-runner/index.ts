// race-runner — HTTP/2-style race-condition harness for business-logic abuse
//
// Sends N parallel requests to the same endpoint and checks whether the
// response set indicates a race (e.g., coupon applied twice, balance went
// negative, two unique IDs returned for what should be one transaction).
//
// All findings → confirmFinding gate.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.0";
import { safeFetch, readBodySafe, headersToObject } from "../_shared/safe-fetch.ts";
import { confirmFinding } from "../_shared/ai-confirm-gate.ts";
import { checkLoopGuard, recordLoopRun } from "../_shared/loop-guard.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};
const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

interface RaceInput {
  targetId: string;
  url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  parallel?: number; // default 20
  successPattern?: string; // regex matching a "success once" indicator
  uniqueIdPattern?: string; // regex extracting unique IDs to count duplicates
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  const supa = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
  let input: RaceInput;
  try {
    input = await req.json();
  } catch {
    return j({ ok: false, error: "invalid json" });
  }
  if (!input.url) return j({ ok: false, error: "url required" });

  if (input.targetId) {
    const guard = await checkLoopGuard(supa, input.targetId, "race-runner", { maxRuns: 6, stallStreak: 3 });
    if (!guard.allow) return j({ ok: false, skipped: true, reason: guard.reason });
  }

  const N = Math.min(Math.max(input.parallel || 20, 5), 40);
  const successRx = input.successPattern ? new RegExp(input.successPattern, "i") : null;
  const idRx = input.uniqueIdPattern ? new RegExp(input.uniqueIdPattern, "ig") : null;

  // Fire N requests as close together as possible
  const promises = Array.from({ length: N }, () =>
    safeFetch(
      input.url,
      {
        method: input.method || "POST",
        headers: input.headers || {},
        body: input.body,
      },
      10000,
    )
      .then(async (r) => ({ status: r.status, body: await readBodySafe(r, 4000), headers: headersToObject(r.headers) }))
      .catch(() => null),
  );
  const results = (await Promise.all(promises)).filter((x): x is NonNullable<typeof x> => !!x);

  // Detect race
  let successCount = 0;
  const ids = new Set<string>();
  const allIds: string[] = [];
  for (const r of results) {
    if (successRx && successRx.test(r.body)) successCount++;
    if (idRx) {
      const m = r.body.match(idRx);
      if (m)
        for (const id of m) {
          ids.add(id);
          allIds.push(id);
        }
    }
  }
  const duplicates = allIds.length - ids.size;

  // Status-code-based fallback signal — used when the caller doesn't supply
  // successPattern/uniqueIdPattern (the common case: vuln-scanner's auto
  // fan-out calls race-runner with just {targetId,url,method,parallel} on
  // financially-sensitive paths). Without this, `raced` was unconditionally
  // false for every auto-triggered race test, since both regex branches
  // short-circuit on null. A correctly-locked endpoint under N parallel
  // identical requests should return at most one 2xx and reject the rest
  // (409/429/400/403); if 2+ requests both succeed, that's the race.
  const statusCounts = new Map<number, number>();
  for (const r of results) statusCounts.set(r.status, (statusCounts.get(r.status) || 0) + 1);
  const twoXxCount = results.filter((r) => r.status >= 200 && r.status < 300).length;
  const statusRaced = !successRx && !idRx && twoXxCount >= 2 && results.length >= 5;

  const raced =
    (successRx && successCount > 1) || // success indicator fired multiple times
    (idRx && allIds.length > ids.size && duplicates >= 2) || // duplicate IDs returned
    statusRaced; // fallback: multiple 2xx where locking should allow one

  if (!raced) return j({ ok: true, raced: false, success_count: successCount, sent: N });

  const sample = results.slice(0, 3);
  const proofType = successRx ? "success_more_than_once" : idRx ? "duplicate_ids_in_race" : "concurrent_2xx_status";
  const verdict = await confirmFinding({
    vulnClass: "race-condition",
    payload: `${N} parallel ${input.method || "POST"} ${input.url}`,
    endpoint: input.url,
    mutated: {
      status: sample[0].status,
      bodySnippet: statusRaced
        ? `${twoXxCount}/${N} requests returned 2xx (status distribution: ${[...statusCounts.entries()].map(([s, c]) => `${s}×${c}`).join(", ")})\n` +
          sample.map((r) => r.body.slice(0, 300)).join("\n---\n")
        : sample.map((r) => r.body.slice(0, 300)).join("\n---\n"),
      length: sample.reduce((s, r) => s + r.body.length, 0),
    },
    deterministicProof: true,
    proofType,
  });
  if (verdict.recommendedAction === "drop_false_positive" || verdict.recommendedAction === "drop_honeypot") {
    return j({ ok: true, raced: true, dropped: verdict.reasoning });
  }

  const isApproval = verdict.recommendedAction === "insert_approval";
  const table = isApproval ? "pending_approvals" : "vulnerability_findings";
  const row: any = isApproval
    ? {
        target_id: input.targetId,
        finding_type: "race-condition",
        severity: "high",
        title: `Race condition — ${successCount > 1 ? `success fired ${successCount}× of ${N}` : `${duplicates} duplicate IDs returned`}`,
        description: verdict.reasoning,
        payload_used: `${N} parallel`,
        confidence_score: verdict.confidence,
        ai_verified: true,
        ai_verification_notes: verdict.reasoning,
        evidence: {
          sent: N,
          success_count: successCount,
          duplicate_ids: duplicates,
          sample_bodies: sample.map((r) => r.body.slice(0, 600)),
        },
      }
    : {
        target_id: input.targetId,
        title: `Race condition exploitable`,
        severity: "high",
        description: verdict.reasoning,
        payload: `${N} parallel`,
        confidence_score: verdict.confidence,
        ai_verified: true,
        triage_reasoning: verdict.reasoning,
        validation_status: "verified",
      };
  const { data } = await supa.from(table).insert(row).select("id").single();
  return j({
    ok: true,
    raced: true,
    finding_id: data?.id,
    sent: N,
    success_count: successCount,
    duplicate_ids: duplicates,
  });
});

function j(b: unknown, s = 200) {
  return new Response(JSON.stringify(b), {
    status: s,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}
