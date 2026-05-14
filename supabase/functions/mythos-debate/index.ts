// Two black-hat agents debate a parameter, agree on a payload, test it,
// then debate whether the result is a real bug or a false positive.
// Agent A = Recon Analyst (sees param, hypothesizes vuln class)
// Agent B = Exploit Strategist (proposes payload, refines based on response)
// Both learn from outcomes and self-correlate.
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");

async function callAgent(role: "A" | "B", systemPrompt: string, userMsg: string, history: any[]): Promise<string> {
  if (!LOVABLE_API_KEY) return `[${role}] (no LLM key) — heuristic mode`;
  try {
    const r = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${LOVABLE_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "google/gemini-2.5-flash",
        messages: [{ role: "system", content: systemPrompt }, ...history, { role: "user", content: userMsg }],
        max_tokens: 400,
      }),
      signal: AbortSignal.timeout(15000),
    });
    if (!r.ok) return `[${role}] LLM error ${r.status}`;
    const d = await r.json();
    return d.choices?.[0]?.message?.content?.trim() || `[${role}] (empty)`;
  } catch (e) {
    return `[${role}] error: ${e instanceof Error ? e.message : "unknown"}`;
  }
}

// ── Safety gate ──────────────────────────────────────────────────────────────
const DESTRUCTIVE_TOKENS = [
  "DROP TABLE",
  "DROP DATABASE",
  "DROP SCHEMA",
  "DROP ",
  "DELETE FROM",
  "TRUNCATE",
  "UPDATE SET",
  "INSERT INTO",
  "SHUTDOWN",
  "ALTER TABLE",
  "GRANT ",
  "REVOKE ",
  "EXEC(",
  "EVAL(",
  "SYSTEM(",
  "XP_CMDSHELL",
  "RM -RF",
  "FORMAT C:",
  "MKFS",
  "DD IF=",
  "; END;",
  "WAITFOR DELAY",
];

function isSafePayload(payload: string): { ok: boolean; matched?: string } {
  if (!payload) return { ok: true };
  const upper = payload.toUpperCase();
  for (const t of DESTRUCTIVE_TOKENS) {
    if (upper.includes(t)) return { ok: false, matched: t };
  }
  return { ok: true };
}

// ── SQL error pattern ────────────────────────────────────────────────────────
const SQL_ERROR_RX = /sql syntax|mysql_|pg_query|SQLSTATE|ORA-\d+|unclosed quotation|syntax error.*SQL|psql:|sqlite_/i;

// ── XSS unescaped check ──────────────────────────────────────────────────────
// Verifies the payload appears LITERALLY unescaped in the body,
// not as HTML entities, not inside an HTML comment, and the
// dangerous angle brackets are present verbatim at that position.
function isPayloadUnescapedInBody(payload: string, body: string): boolean {
  if (!body.includes(payload)) return false;

  const idx = body.indexOf(payload);
  const surrounding = body.slice(Math.max(0, idx - 100), idx + payload.length + 100);

  // If the area is inside an HTML comment — not exploitable
  if (surrounding.includes("<!--") && surrounding.includes("-->")) return false;

  // If angle brackets are entity-encoded anywhere near the payload — escaped
  if (surrounding.includes("&lt;") || surrounding.includes("&gt;")) return false;
  if (surrounding.includes("&#60;") || surrounding.includes("&#62;")) return false;

  // The actual payload slice must contain the literal dangerous chars
  const payloadSlice = body.slice(idx, idx + payload.length);
  const hasLiteralAngle = payloadSlice.includes("<") && payloadSlice.includes(">");
  if (!hasLiteralAngle) return false;

  // Response must have grown by at least 70% of the payload length
  // (rules out coincidental substring matches in existing page content)
  return true;
}

// ── Probe — baseline vs mutated comparison ───────────────────────────────────
async function probe(
  url: string,
  paramName: string,
  payload: string,
): Promise<{
  status: number;
  bodyLen: number;
  bodySnippet: string;
  reflected: boolean;
  errorSig: boolean;
  blocked?: boolean;
  baselineStatus: number;
  baselineLen: number;
  meaningfulDiff: boolean;
  diffReason: string;
  timingDelta: number;
  xssUnescaped: boolean;
}> {
  const safe = isSafePayload(payload);
  if (!safe.ok) {
    return {
      status: 0,
      bodyLen: 0,
      bodySnippet: `BLOCKED_BY_SAFETY:${safe.matched}`,
      reflected: false,
      errorSig: false,
      blocked: true,
      baselineStatus: 0,
      baselineLen: 0,
      meaningfulDiff: false,
      diffReason: "blocked by safety filter",
      timingDelta: 0,
      xssUnescaped: false,
    };
  }

  try {
    // Step 1 — baseline (no payload)
    const baseT0 = Date.now();
    const baseResp = await fetch(url, {
      signal: AbortSignal.timeout(8000),
      redirect: "manual",
    });
    const baseTime = Date.now() - baseT0;
    const baseBody = await baseResp.text();

    // Step 2 — mutated (with payload)
    const u = new URL(url);
    u.searchParams.set(paramName, payload);
    const mutT0 = Date.now();
    const r = await fetch(u.toString(), {
      signal: AbortSignal.timeout(8000),
      redirect: "manual",
    });
    const mutTime = Date.now() - mutT0;
    const body = await r.text();

    const timingDelta = mutTime - baseTime;

    // Step 3 — meaningful difference analysis
    const lenDiff = Math.abs(body.length - baseBody.length);
    const lenDiffPct = lenDiff / (baseBody.length || 1);

    const SQL_ERR =
      /sql syntax|mysql_fetch|pg_query|SQLSTATE|ORA-\d+|unclosed quotation|syntax error.*sql|psql:|sqlite_/i;
    const STACK = /at [A-Za-z]+\.[A-Za-z]+\(|stack trace|traceback \(most recent|exception in thread/i;
    const SECRETS = /root:x:0:0|\/bin\/bash|aws_secret_access_key|AKIA[0-9A-Z]{16}|private_key/i;

    const hasSqlError = SQL_ERR.test(body) && !SQL_ERR.test(baseBody);
    const hasStackTrace = STACK.test(body) && !STACK.test(baseBody);
    const hasSecrets = SECRETS.test(body) && !SECRETS.test(baseBody);
    const hasTimingHit = timingDelta > 4500;
    const statusChanged = r.status !== baseResp.status && !(r.status === 200 && baseResp.status === 200);
    const bigBodyDiff = lenDiffPct > 0.4 && lenDiff > 1000 && statusChanged;

    // ── XSS detection — strict unescaped check ──────────────────────────────
    // Must satisfy ALL conditions:
    // 1. Payload is NOT in baseline (it's not existing page content)
    // 2. Payload IS in mutated response
    // 3. Payload appears literally unescaped (not entity-encoded)
    // 4. Response grew by at least 70% of payload length (real reflection)
    // 5. Payload contains actual XSS-dangerous characters
    const isXssPayload = /<|onerror|onload|javascript:|alert|script/i.test(payload);
    const payloadInBase = baseBody.includes(payload);
    const payloadInMutated = body.includes(payload);
    const bodySizeGrowth = body.length - baseBody.length;
    const grewByPayloadSize = bodySizeGrowth >= payload.length * 0.7;

    const xssUnescaped =
      isXssPayload &&
      !payloadInBase &&
      payloadInMutated &&
      grewByPayloadSize &&
      isPayloadUnescapedInBody(payload, body);

    // Only treat as meaningful XSS if all strict conditions met
    const hasHtmlExec = xssUnescaped;

    const meaningfulDiff = hasSqlError || hasStackTrace || hasSecrets || hasHtmlExec || hasTimingHit || bigBodyDiff;

    let diffReason = "no meaningful difference — likely false positive";
    if (hasSqlError) diffReason = "SQL error string appeared in response";
    else if (hasStackTrace) diffReason = "stack trace exposed";
    else if (hasSecrets) diffReason = "sensitive data pattern matched";
    else if (hasHtmlExec) diffReason = "XSS payload reflected literally unescaped — confirmed injection point";
    else if (hasTimingHit) diffReason = `timing delta ${timingDelta}ms — possible blind injection`;
    else if (bigBodyDiff)
      diffReason = `response size changed ${lenDiff}b (${Math.round(lenDiffPct * 100)}%) with status change`;

    // Log why XSS was rejected when payload was XSS but check failed
    let xssRejectReason = "";
    if (isXssPayload && !xssUnescaped) {
      if (payloadInBase) xssRejectReason = "payload already in baseline (existing page content)";
      else if (!payloadInMutated) xssRejectReason = "payload not reflected in response";
      else if (!grewByPayloadSize)
        xssRejectReason = `response only grew ${bodySizeGrowth}b — payload (${payload.length}b) not fully reflected`;
      else xssRejectReason = "payload appears HTML-entity encoded or inside comment — not executable";
    }

    return {
      status: r.status,
      bodyLen: body.length,
      // Include XSS reject reason in snippet for debugging
      bodySnippet: (xssRejectReason ? `[XSS-REJECT: ${xssRejectReason}] ` : "") + body.slice(0, 400),
      reflected: payloadInMutated && !payloadInBase,
      errorSig: hasSqlError,
      baselineStatus: baseResp.status,
      baselineLen: baseBody.length,
      meaningfulDiff,
      diffReason,
      timingDelta,
      xssUnescaped,
    };
  } catch {
    return {
      status: 0,
      bodyLen: 0,
      bodySnippet: "",
      reflected: false,
      errorSig: false,
      baselineStatus: 0,
      baselineLen: 0,
      meaningfulDiff: false,
      diffReason: "request failed",
      timingDelta: 0,
      xssUnescaped: false,
    };
  }
}

// ── Main handler ─────────────────────────────────────────────────────────────
serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });
  try {
    const { targetId, runId, endpointUrl, paramName, paramValue, vulnClassHint } = await req.json();
    if (!targetId || !endpointUrl || !paramName) throw new Error("targetId, endpointUrl, paramName required");

    const db = createClient(SUPABASE_URL, SERVICE_KEY);
    const transcript: any[] = [];
    const history: any[] = [];

    const sysA = `You are Agent A — black-hat recon analyst. You analyze HTTP parameters and hypothesize what vulnerability classes (SQLi, XSS, SSRF, IDOR, RCE, SSTI, LFI, etc) might apply. Be SPECIFIC, terse (≤80 words). Talk to Agent B as a teammate.`;
    const sysB = `You are Agent B — black-hat exploit strategist. You propose CONCRETE payloads given a hypothesis. Be SPECIFIC (raw payload), terse (≤80 words). Talk to Agent A as a teammate.`;

    // Round 1 — Agent A analyzes the param
    const a1 = await callAgent(
      "A",
      sysA,
      `Param: ${paramName}=${paramValue}\nURL: ${endpointUrl}\nHint: ${vulnClassHint || "none"}\n\nWhat vuln class fits best? Why?`,
      [],
    );
    transcript.push({ agent: "A", round: 1, msg: a1 });
    history.push({ role: "user", content: `Agent A says: ${a1}` });

    // Round 2 — Agent B proposes a read-only payload
    let b1 = await callAgent(
      "B",
      sysB,
      `Agent A analysis: ${a1}\n\nPropose ONE concrete READ-ONLY payload to test. Output ONLY the raw payload on the first line, then 1-line rationale.\n\nSAFETY RULES (mandatory):\n- READ-ONLY only. NEVER use DROP, DELETE, TRUNCATE, UPDATE, INSERT, SHUTDOWN, GRANT, REVOKE, ALTER, EXEC, xp_cmdshell, rm -rf, format, mkfs.\n- Prefer error-based / boolean-based / reflection probes (e.g. ' OR 1=1--, <svg onload=alert(1)>, ../../../etc/passwd, {{7*7}}).`,
      [],
    );
    transcript.push({ agent: "B", round: 2, msg: b1 });
    let proposedPayload = b1
      .split("\n")[0]
      .trim()
      .replace(/^[`"']|[`"']$/g, "");

    // Safety re-prompt
    let safetyCheck = isSafePayload(proposedPayload);
    if (!safetyCheck.ok) {
      await db.from("scan_logs").insert({
        target_id: targetId,
        log_type: "info",
        message: `🛡️ Safety filter blocked destructive payload: ${proposedPayload.slice(0, 50)} (${safetyCheck.matched})`,
        metadata: { run_id: runId, phase: "debate-safety-block" },
      });
      const b1retry = await callAgent(
        "B",
        sysB,
        `Your previous payload "${proposedPayload.slice(0, 60)}" contains destructive operations (${safetyCheck.matched}) and was BLOCKED. Propose a READ-ONLY test payload that cannot modify data. Output ONLY the raw payload on the first line.`,
        [],
      );
      transcript.push({
        agent: "B",
        round: 2.5,
        msg: `[retry after safety block] ${b1retry}`,
      });
      const retryPayload = b1retry
        .split("\n")[0]
        .trim()
        .replace(/^[`"']|[`"']$/g, "");
      if (isSafePayload(retryPayload).ok) {
        proposedPayload = retryPayload;
        b1 = b1retry;
      } else {
        await db.from("scan_logs").insert({
          target_id: targetId,
          log_type: "info",
          message: `🛡️ Safety: Agent B proposed destructive payload twice — debate aborted`,
          metadata: { run_id: runId, phase: "debate-safety-abort" },
        });
        return new Response(JSON.stringify({ aborted: "safety", fpVerdict: "inconclusive", confidence: 0 }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
    }

    // Execute the agreed (safe) payload
    const probe1 = await probe(endpointUrl, paramName, proposedPayload);
    transcript.push({
      agent: "system",
      round: 3,
      msg: `EXECUTED: status=${probe1.status} len=${probe1.bodyLen} reflected=${probe1.reflected} errSig=${probe1.errorSig} meaningfulDiff=${probe1.meaningfulDiff} diffReason=${probe1.diffReason} timingDelta=${probe1.timingDelta}ms xssUnescaped=${probe1.xssUnescaped}`,
    });

    // Round 4 — Agent A debates if this is a real bug or FP
    const a2 = await callAgent(
      "A",
      sysA,
      `Result of payload "${proposedPayload}":
status=${probe1.status} (baseline=${probe1.baselineStatus})
length=${probe1.bodyLen}b (baseline=${probe1.baselineLen}b)
reflected=${probe1.reflected}
xss_unescaped=${probe1.xssUnescaped}
error_signature=${probe1.errorSig}
meaningful_diff=${probe1.meaningfulDiff}
diff_reason=${probe1.diffReason}
timing_delta=${probe1.timingDelta}ms
Body snippet: ${probe1.bodySnippet.slice(0, 200)}

Is this a TRUE bug or FALSE POSITIVE? Be SKEPTICAL.
IMPORTANT: 
- if meaningful_diff is false → almost always false positive
- if xss_unescaped is false for an XSS payload → false positive (browser won't execute it)
- if diff_reason contains XSS-REJECT → the payload was encoded or not reflected properly
State verdict + 1-line reason.`,
      history,
    );
    transcript.push({ agent: "A", round: 4, msg: a2 });

    // Round 5 — Agent B challenges Agent A
    const b2 = await callAgent(
      "B",
      sysB,
      `Agent A's verdict: ${a2}\n\nDo you AGREE or DISAGREE? If FP, explain why. If real bug, what would be the next escalation step? ≤60 words.`,
      history,
    );
    transcript.push({ agent: "B", round: 5, msg: b2 });

    // ── Verdict logic ─────────────────────────────────────────────────────────
    const aSaysFP = /false positive|not a bug|FP|not vulnerable|no vuln/i.test(a2);
    const bSaysFP = /false positive|not a bug|FP|agree.*FP|agree.*false/i.test(b2);
    const aSaysTP = /true positive|real bug|exploitable|vulnerable|confirmed/i.test(a2);
    const bSaysTP = /agree|true positive|real bug|exploitable|confirmed/i.test(b2) && !bSaysFP;
    const bothAgreeFP = aSaysFP && bSaysFP;
    const bothAgreeTP = aSaysTP && bSaysTP;

    const sqlErrorHit = SQL_ERROR_RX.test(probe1.bodySnippet);

    let fpVerdict: "true_positive" | "false_positive" | "inconclusive";
    let confidence: number;

    if (probe1.blocked) {
      fpVerdict = "inconclusive";
      confidence = 0;
    } else if (!probe1.meaningfulDiff && probe1.status !== 0) {
      // Response did not meaningfully change — false positive
      fpVerdict = "false_positive";
      confidence = 90;
    } else if (probe1.diffReason === "sensitive data pattern matched") {
      fpVerdict = "true_positive";
      confidence = 95;
    } else if (probe1.status >= 500 && sqlErrorHit) {
      fpVerdict = "true_positive";
      confidence = 90;
    } else if (probe1.diffReason === "stack trace exposed") {
      fpVerdict = "true_positive";
      confidence = 85;
    } else if (probe1.xssUnescaped) {
      // XSS confirmed only when strict unescaped check passes
      // Additional check: agents must not both disagree
      if (bothAgreeFP) {
        // Agents disagree with our check — downgrade to needs_review
        fpVerdict = "true_positive";
        confidence = 70;
      } else {
        fpVerdict = "true_positive";
        confidence = 82;
      }
    } else if (probe1.timingDelta > 4500) {
      fpVerdict = "true_positive";
      confidence = 75;
    } else if (probe1.meaningfulDiff && bothAgreeTP) {
      fpVerdict = "true_positive";
      confidence = 70;
    } else if (probe1.meaningfulDiff && !bothAgreeFP) {
      fpVerdict = "inconclusive";
      confidence = 50;
    } else if (bothAgreeFP) {
      fpVerdict = "false_positive";
      confidence = 85;
    } else if (probe1.status === 0) {
      fpVerdict = "inconclusive";
      confidence = 30;
    } else {
      fpVerdict = "false_positive";
      confidence = 75;
    }

    // ── Round 6 — Skeptic critique → refined payload → re-probe ──────────────
    let probe2: typeof probe1 | null = null;
    let refinedPayload: string | null = null;
    let skepticMsg: string | null = null;
    const inconclusive =
      fpVerdict === "inconclusive" || (fpVerdict === "false_positive" && confidence < 90 && probe1.status !== 0);

    if (inconclusive && !probe1.blocked) {
      const sysSkeptic = `You are the Skeptic — a senior bug-bounty triager. Your only job is to detect WEAK signals the first payload missed and propose ONE refined READ-ONLY payload that would PROVE or DISPROVE the bug. Be terse (≤60 words). Output: line 1 = raw payload only; line 2 = 1-line rationale.`;
      const skepticUserMsg = `First payload "${proposedPayload}" produced:\nstatus=${probe1.status} (baseline=${probe1.baselineStatus})\nlen=${probe1.bodyLen}b (baseline=${probe1.baselineLen}b)\ndiff_reason=${probe1.diffReason}\ntiming=${probe1.timingDelta}ms\nverdict=${fpVerdict} confidence=${confidence}\n\nAgent A: ${a2}\nAgent B: ${b2}\n\nPropose ONE sharper READ-ONLY payload that would resolve the ambiguity (e.g. timing-based, error-based, boundary-case). Forbidden: DROP/DELETE/UPDATE/INSERT/TRUNCATE/SHUTDOWN/EXEC/rm -rf.`;
      skepticMsg = await callAgent("A", sysSkeptic, skepticUserMsg, []);
      transcript.push({ agent: "skeptic", round: 6, msg: skepticMsg });
      const candidate = skepticMsg
        .split("\n")[0]
        .trim()
        .replace(/^[`"']|[`"']$/g, "");
      if (candidate && candidate !== proposedPayload && isSafePayload(candidate).ok) {
        refinedPayload = candidate;
        probe2 = await probe(endpointUrl, paramName, refinedPayload);
        transcript.push({
          agent: "system",
          round: 7,
          msg: `SKEPTIC RETEST: status=${probe2.status} len=${probe2.bodyLen} reflected=${probe2.reflected} errSig=${probe2.errorSig} meaningfulDiff=${probe2.meaningfulDiff} diffReason=${probe2.diffReason} timingDelta=${probe2.timingDelta}ms xssUnescaped=${probe2.xssUnescaped}`,
        });

        // Re-score using probe2 if it produced a stronger signal
        let v2: typeof fpVerdict = fpVerdict;
        let c2 = confidence;
        const sql2 = SQL_ERROR_RX.test(probe2.bodySnippet);
        if (probe2.diffReason === "sensitive data pattern matched") {
          v2 = "true_positive";
          c2 = 95;
        } else if (probe2.status >= 500 && sql2) {
          v2 = "true_positive";
          c2 = 92;
        } else if (probe2.diffReason === "stack trace exposed") {
          v2 = "true_positive";
          c2 = 88;
        } else if (probe2.xssUnescaped) {
          v2 = "true_positive";
          c2 = 85;
        } else if (probe2.timingDelta > 4500) {
          v2 = "true_positive";
          c2 = 80;
        } else if (probe2.meaningfulDiff) {
          v2 = "inconclusive";
          c2 = Math.max(c2, 60);
        } else {
          v2 = "false_positive";
          c2 = Math.max(c2, 80);
        }

        if (c2 > confidence || (v2 === "true_positive" && fpVerdict !== "true_positive")) {
          fpVerdict = v2;
          confidence = c2;
        }
      }
    }

    // Self-correlation learnings
    const learnA = `Param ${paramName}: hypothesis "${a1.slice(0, 80)}…". Verdict: ${fpVerdict} (${confidence}%). diffReason: ${probe1.diffReason}${probe2 ? ` | skeptic-retest: ${probe2.diffReason}` : ""}`;
    const learnB = `Payload "${proposedPayload.slice(0, 60)}" → ${fpVerdict}. ${probe1.meaningfulDiff ? "Meaningful diff — promote pattern." : "No diff — deprioritize this template."}${refinedPayload ? ` | Skeptic refined: "${refinedPayload.slice(0, 40)}"` : ""}`;

    const { data: debateRow } = await db
      .from("mythos_debates")
      .insert({
        target_id: targetId,
        run_id: runId ?? null,
        endpoint_url: endpointUrl,
        param_name: paramName,
        param_value: paramValue ?? null,
        vuln_class: vulnClassHint ?? null,
        transcript,
        agreed_payload: proposedPayload,
        agreed_rationale: b1,
        test_result: probe1,
        fp_verdict: fpVerdict,
        fp_reasoning: `${a2}\n---\n${b2}`,
        confidence_score: confidence,
        agent_a_learning: learnA,
        agent_b_learning: learnB,
      })
      .select()
      .single();

    // Stream phase logs
    await db.from("scan_logs").insert([
      {
        target_id: targetId,
        log_type: "thought",
        message: `🥷 Agent A: ${a1.slice(0, 120)}`,
        metadata: { run_id: runId, debate_id: debateRow?.id, phase: "debate-a1" },
      },
      {
        target_id: targetId,
        log_type: "thought",
        message: `🥷 Agent B: ${b1.slice(0, 120)}`,
        metadata: { run_id: runId, debate_id: debateRow?.id, phase: "debate-b1" },
      },
      {
        target_id: targetId,
        log_type: "action",
        message: `⚔️ Executed: ${proposedPayload.slice(0, 80)} → ${probe1.status} (${probe1.bodyLen}b)`,
        metadata: { run_id: runId, debate_id: debateRow?.id, phase: "debate-exec" },
      },
      {
        target_id: targetId,
        log_type: fpVerdict === "true_positive" ? "result" : "info",
        message: `🧐 Verdict: ${fpVerdict} (${confidence}% conf) — ${probe1.diffReason} | xssUnescaped=${probe1.xssUnescaped} | baseline=${probe1.baselineLen}b → mutated=${probe1.bodyLen}b | Δtime=${probe1.timingDelta}ms | status=${probe1.baselineStatus}→${probe1.status}`,
        metadata: { run_id: runId, debate_id: debateRow?.id, phase: "debate-verdict" },
      },
    ]);

    // ── Escalation pipeline ──────────────────────────────────────────────────
    if (fpVerdict === "true_positive" && debateRow?.id && confidence >= 55) {
      const validationStatus = confidence >= 75 ? "debate_confirmed" : "needs_review";
      const title = `Debate-confirmed: ${vulnClassHint || "auto"} via ${paramName}`;

      const { data: finding } = await db
        .from("vulnerability_findings")
        .insert({
          target_id: targetId,
          title,
          severity: confidence >= 80 ? "high" : confidence >= 75 ? "medium" : "low",
          description: `Two-agent debate verdict: ${fpVerdict} (${confidence}% conf)\n\n**Diff reason**: ${probe1.diffReason}\n**XSS unescaped**: ${probe1.xssUnescaped}\n\n**Agent A**: ${a2}\n\n**Agent B**: ${b2}`,
          payload: proposedPayload,
          poc: `${endpointUrl}?${paramName}=${encodeURIComponent(proposedPayload)}`,
          affected_url: endpointUrl,
          confidence_score: confidence,
          confidence_level: confidence >= 75 ? "high" : "medium",
          triage_reasoning: `Agent A: ${a1}\nAgent B: ${b1}\nResult: ${JSON.stringify(probe1)}\nDebate: ${a2} | ${b2}`,
          validation_status: validationStatus,
          hard_evidence: {
            baseline_status: probe1.baselineStatus,
            baseline_length: probe1.baselineLen,
            mutated_status: probe1.status,
            mutated_length: probe1.bodyLen,
            diff_reason: probe1.diffReason,
            xss_unescaped: probe1.xssUnescaped,
            timing_delta_ms: probe1.timingDelta,
            meaningful_diff: probe1.meaningfulDiff,
            body_snippet: probe1.bodySnippet,
            skeptic_round: probe2
              ? {
                  refined_payload: refinedPayload,
                  skeptic_msg: skepticMsg,
                  probe: probe2,
                }
              : null,
          },
        })
        .select("id")
        .single();

      if (confidence >= 75 && finding?.id) {
        fetch(`${SUPABASE_URL}/functions/v1/exploit-engine`, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${SERVICE_KEY}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ findingId: finding.id, targetId }),
        }).catch((e) => console.error("exploit-engine dispatch failed:", e));

        await db.from("scan_jobs").insert({
          target_id: targetId,
          job_type: "exploit",
          priority: 9,
          payload: { findingId: finding.id },
        });

        await db.from("scan_logs").insert({
          target_id: targetId,
          log_type: "result",
          message: `🚀 Escalating to exploit engine: ${title} (${confidence}% conf) — ${probe1.diffReason}`,
          metadata: {
            run_id: runId,
            debate_id: debateRow.id,
            finding_id: finding.id,
            phase: "debate-escalate",
          },
        });
      } else if (finding?.id) {
        await db.from("scan_logs").insert({
          target_id: targetId,
          log_type: "info",
          message: `🟧 needs_review: ${title} (${confidence}% conf — below auto-escalate threshold) — ${probe1.diffReason}`,
          metadata: {
            run_id: runId,
            debate_id: debateRow.id,
            finding_id: finding.id,
            phase: "debate-needs-review",
          },
        });
      }
    }

    return new Response(
      JSON.stringify({
        debateId: debateRow?.id,
        fpVerdict,
        confidence,
        agreedPayload: proposedPayload,
        diffReason: probe1.diffReason,
        meaningfulDiff: probe1.meaningfulDiff,
        xssUnescaped: probe1.xssUnescaped,
        transcript,
      }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } },
    );
  } catch (e) {
    console.error("mythos-debate error:", e);
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : String(e) }), {
      status: 200,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
