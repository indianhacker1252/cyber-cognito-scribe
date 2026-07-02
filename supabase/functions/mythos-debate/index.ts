// Two black-hat agents debate a parameter, agree on a payload, test it,
// then debate whether the result is a real bug or a false positive.
// Agent A = Recon Analyst (sees param, hypothesizes vuln class)
// Agent B = Exploit Strategist (proposes payload, refines based on response)
// Both learn from outcomes and self-correlate.
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import {
  AiCreditsExhaustedError,
  isCreditExhaustionResponse,
  areCreditsRecentlyExhausted,
  markCreditsExhausted,
} from "../_shared/ai-credits.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");

// Per-instance fast-fail: once we see one 402, every subsequent callAgent in
// this isolate throws immediately so we don't fan-out 30 more LLM calls.
let CREDITS_DEAD = false;

async function callAgent(role: "A" | "B", systemPrompt: string, userMsg: string, history: any[]): Promise<string> {
  if (CREDITS_DEAD) throw new AiCreditsExhaustedError();
  if (!LOVABLE_API_KEY) return "";
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
    if (!r.ok) {
      let body = "";
      try {
        body = await r.text();
      } catch {
        /* ignore */
      }
      if (isCreditExhaustionResponse(r.status, body)) {
        CREDITS_DEAD = true;
        throw new AiCreditsExhaustedError(`HTTP ${r.status}: ${body.slice(0, 120)}`);
      }
      // Non-fatal upstream error — return empty so callers can skip safely.
      return "";
    }
    const d = await r.json();
    return d.choices?.[0]?.message?.content?.trim() || "";
  } catch (e) {
    if (e instanceof AiCreditsExhaustedError) throw e;
    return "";
  }
}

/** Guard: never let an LLM-error string become a payload. */
function isInvalidPayload(p: string): boolean {
  if (!p || p.length < 1) return true;
  if (/^\s*\[[A-Z]\]\s/.test(p)) return true;
  if (/^\s*(LLM error|AI credits|bllmerror|\(empty\)|\(no LLM key\)|error:)/i.test(p)) return true;
  return false;
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
];

// Read-only allowlist: time-based blind probes capped at 5s on read-only DBs (MSSQL, etc).
// WAITFOR DELAY '0:0:5' is non-destructive but blocked if duration > 5s.
function isAllowedReadOnlyTiming(payload: string): boolean {
  const upper = payload.toUpperCase();
  const wait = upper.match(/WAITFOR\s+DELAY\s+['"]?0:0:(\d{1,2})/);
  if (wait) return parseInt(wait[1], 10) <= 5;
  const sleep = upper.match(/SLEEP\s*\(\s*(\d{1,2})\s*\)/);
  if (sleep) return parseInt(sleep[1], 10) <= 5;
  return true;
}

function isSafePayload(payload: string): { ok: boolean; matched?: string } {
  if (!payload) return { ok: true };
  const upper = payload.toUpperCase();
  for (const t of DESTRUCTIVE_TOKENS) {
    if (upper.includes(t)) return { ok: false, matched: t };
  }
  if (!isAllowedReadOnlyTiming(payload)) {
    return { ok: false, matched: "TIMING>5s" };
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
  locationHeader?: string;
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

  const FETCH_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
  } as const;
  try {
    // Step 1 — baseline (no payload)
    const baseT0 = Date.now();
    const baseResp = await fetch(url, {
      signal: AbortSignal.timeout(8000),
      redirect: "manual",
      headers: FETCH_HEADERS,
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
      headers: FETCH_HEADERS,
    });
    const mutTime = Date.now() - mutT0;
    const body = await r.text();
    // Capture Location header for open-redirect detection
    const locationHeader = r.headers.get("location") || "";

    const timingDelta = mutTime - baseTime;

    // Step 3 — meaningful difference analysis
    const lenDiff = Math.abs(body.length - baseBody.length);
    const lenDiffPct = lenDiff / (baseBody.length || 1);

    const SQL_ERR =
      /sql syntax|mysql_fetch|pg_query|SQLSTATE|ORA-\d+|unclosed quotation|syntax error.*sql|psql:|sqlite_|odbc.*error|microsoft.*odbc|System\.Data\.SqlClient/i;
    const STACK = /at [A-Za-z]+\.[A-Za-z]+\(|stack trace|traceback \(most recent|exception in thread/i;
    const SECRETS = /root:x:0:0|\/bin\/bash|aws_secret_access_key|AKIA[0-9A-Z]{16}|private_key/i;

    const hasSqlError = SQL_ERR.test(body) && !SQL_ERR.test(baseBody);
    const hasStackTrace = STACK.test(body) && !STACK.test(baseBody);
    const hasSecrets = SECRETS.test(body) && !SECRETS.test(baseBody);
    const hasTimingHit = timingDelta > 4500;
    const statusChanged = r.status !== baseResp.status && !(r.status === 200 && baseResp.status === 200);
    const bigBodyDiff = lenDiffPct > 0.4 && lenDiff > 1000 && statusChanged;

    // ── NEW: SQLi diff-pair detection ──────────────────────────────────────
    // Real SQLi often returns same length on a single mutated probe. Compare
    // a TRUE-twin against a FALSE-twin and a SYNTAX-BREAK twin — boolean-based
    // evidence even without error leakage. Eliminates the FP-FP-FP loop on
    // targets like testaspnet.vulnweb.com.
    const looksSqli = /('|"|union|select|or\s+1=1|and\s+1=|--|sleep\(|benchmark\()/i.test(payload);
    let sqliDiffPair = false;
    let sqliDiffReason = "";
    if (looksSqli && !hasSqlError && !hasStackTrace) {
      try {
        const uTrue = new URL(url);
        uTrue.searchParams.set(paramName, "1' OR '1'='1");
        const uFalse = new URL(url);
        uFalse.searchParams.set(paramName, "1' AND '1'='2");
        const uBreak = new URL(url);
        uBreak.searchParams.set(paramName, "1''\"\\");
        const [tR, fR, bR] = await Promise.all([
          fetch(uTrue.toString(), {
            signal: AbortSignal.timeout(12000),
            redirect: "manual",
            headers: FETCH_HEADERS,
          }).catch(() => null),
          fetch(uFalse.toString(), {
            signal: AbortSignal.timeout(12000),
            redirect: "manual",
            headers: FETCH_HEADERS,
          }).catch(() => null),
          fetch(uBreak.toString(), {
            signal: AbortSignal.timeout(12000),
            redirect: "manual",
            headers: FETCH_HEADERS,
          }).catch(() => null),
        ]);
        const tB = tR ? await tR.text() : "";
        const fB = fR ? await fR.text() : "";
        const bB = bR ? await bR.text() : "";
        const tfDelta = Math.abs(tB.length - fB.length);
        const tfDeltaPct = tfDelta / (Math.max(tB.length, fB.length) || 1);
        const breakErr = SQL_ERR.test(bB) && !SQL_ERR.test(baseBody);
        const breakStatus500 = bR && bR.status >= 500 && baseResp.status < 500;
        if (breakErr) {
          sqliDiffPair = true;
          sqliDiffReason = "syntax-break twin leaked SQL error";
        } else if (breakStatus500) {
          sqliDiffPair = true;
          sqliDiffReason = `syntax-break twin → ${bR!.status} (baseline ${baseResp.status})`;
        } else if (tfDelta > 200 && tfDeltaPct > 0.05) {
          sqliDiffPair = true;
          sqliDiffReason = `boolean diff: TRUE=${tB.length}b vs FALSE=${fB.length}b (Δ${tfDelta}b)`;
        }
      } catch {
        /* ignore twin errors */
      }
    }

    // ── XSS detection — strict unescaped check ──────────────────────────────
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

    const hasHtmlExec = xssUnescaped;

    // Open redirect detection: payload contained an external URL AND the
    // response is a 3xx redirect to an external host. This is a real confirmed
    // finding — the server accepted our URL and redirected to it — but
    // meaningfulDiff was always false for this case because none of the
    // existing checks (sqlError/stack/secrets/xss/timing/body-size) fire on a
    // clean 301. Result: every open redirect was silently marked false_positive.
    const payloadIsExternalUrl = /^https?:\/\/|^\/\//.test(payload.trim());
    const locationIsExternal =
      locationHeader &&
      !locationHeader.startsWith("/") &&
      (() => {
        try {
          return new URL(locationHeader).host !== new URL(url).host;
        } catch {
          return false;
        }
      })();
    const isOpenRedirect =
      payloadIsExternalUrl &&
      [301, 302, 303, 307, 308].includes(r.status) &&
      locationIsExternal &&
      ![301, 302, 303, 307, 308].includes(baseResp.status); // baseline was NOT already redirecting

    const meaningfulDiff =
      hasSqlError ||
      hasStackTrace ||
      hasSecrets ||
      hasHtmlExec ||
      hasTimingHit ||
      bigBodyDiff ||
      sqliDiffPair ||
      isOpenRedirect;

    let diffReason = "no meaningful difference — likely false positive";
    if (hasSqlError) diffReason = "SQL error string appeared in response";
    else if (hasStackTrace) diffReason = "stack trace exposed";
    else if (hasSecrets) diffReason = "sensitive data pattern matched";
    else if (hasHtmlExec) diffReason = "XSS payload reflected literally unescaped — confirmed injection point";
    else if (hasTimingHit) diffReason = `timing delta ${timingDelta}ms — possible blind injection`;
    else if (sqliDiffPair) diffReason = `SQLi diff-pair confirmed: ${sqliDiffReason}`;
    else if (isOpenRedirect)
      diffReason = `Open redirect confirmed: server redirected to external host ${locationHeader} (${r.status})`;
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
      locationHeader,
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

// ─── BINARY JUDGE (replaces 20-agent debate fan-out) ─────────────────────────
// Single decisive LLM call: TP / FP / inconclusive + confidence score.
// If credits are dead, falls back to deterministic heuristic scoring.
async function binaryJudge(
  db: any,
  targetId: string,
  endpointUrl: string,
  paramName: string,
  paramValue: string,
  vulnClassHint: string,
  iteration: number,
): Promise<{
  verdict: "true_positive" | "false_positive" | "inconclusive";
  confidence: number;
  reasoning: string;
  shouldExploit: boolean;
}> {
  // Fast path: if credits dead, use deterministic heuristic
  if (CREDITS_DEAD || !Deno.env.get("LOVABLE_API_KEY")) {
    return deterministicJudge(endpointUrl, paramName, paramValue, vulnClassHint);
  }

  // Check sentinel
  if (await areCreditsRecentlyExhausted(db, targetId, 10)) {
    return deterministicJudge(endpointUrl, paramName, paramValue, vulnClassHint);
  }

  const prompt = `You are a senior penetration tester reviewing a potential vulnerability signal.

Target endpoint: ${endpointUrl}
Parameter: ${paramName} = ${paramValue || "empty"}
Suspected vulnerability class: ${vulnClassHint}
Iteration: ${iteration}

Based on this parameter name and endpoint pattern, give a binary verdict:
- true_positive: parameter is injectable and this endpoint is worth actively exploiting
- false_positive: parameter is safe / endpoint is not injectable
- inconclusive: need more data (only if truly uncertain)

Return JSON only: { "verdict": "true_positive"|"false_positive"|"inconclusive", "confidence": 0-100, "reasoning": "1 sentence", "shouldExploit": true|false }`;

  try {
    const r = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${Deno.env.get("LOVABLE_API_KEY")}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "google/gemini-2.5-flash-lite", // cheapest model for this gate
        messages: [
          {
            role: "system",
            content: "You are a binary vulnerability classifier. Return only valid JSON. Never refuse.",
          },
          { role: "user", content: prompt },
        ],
        max_tokens: 150,
        temperature: 0.1,
      }),
      signal: AbortSignal.timeout(12000),
    });

    if (!r.ok) {
      const body = await r.text().catch(() => "");
      if (isCreditExhaustionResponse(r.status, body)) {
        CREDITS_DEAD = true;
        await markCreditsExhausted(db, { targetId, phase: "binary-judge" });
      }
      return deterministicJudge(endpointUrl, paramName, paramValue, vulnClassHint);
    }

    const data = await r.json();
    const raw = data.choices?.[0]?.message?.content?.trim() || "{}";
    const clean = raw.replace(/```json|```/g, "").trim();
    const parsed = JSON.parse(clean);
    return {
      verdict: parsed.verdict || "inconclusive",
      confidence: parsed.confidence || 50,
      reasoning: parsed.reasoning || "",
      shouldExploit:
        parsed.shouldExploit === true || (parsed.verdict === "true_positive" && (parsed.confidence || 0) >= 55),
    };
  } catch (e) {
    if (e instanceof AiCreditsExhaustedError) {
      CREDITS_DEAD = true;
      await markCreditsExhausted(db, { targetId, phase: "binary-judge" });
    }
    return deterministicJudge(endpointUrl, paramName, paramValue, vulnClassHint);
  }
}

// Deterministic fallback when AI credits are exhausted
// Uses parameter name semantics and endpoint patterns to score without LLM
function deterministicJudge(
  endpointUrl: string,
  paramName: string,
  _paramValue: string,
  vulnClassHint: string,
): {
  verdict: "true_positive" | "false_positive" | "inconclusive";
  confidence: number;
  reasoning: string;
  shouldExploit: boolean;
} {
  let score = 40; // baseline
  const param = paramName.toLowerCase();
  const url = endpointUrl.toLowerCase();

  // High-value injectable parameter names
  const INJECTABLE_PARAMS = [
    "id",
    "uid",
    "user_id",
    "file",
    "path",
    "url",
    "redirect",
    "next",
    "return",
    "page",
    "search",
    "q",
    "query",
    "cmd",
    "exec",
    "command",
    "template",
    "include",
    "src",
    "dest",
    "target",
    "ref",
    "token",
    "key",
    "api_key",
    "order",
    "sort",
  ];
  if (INJECTABLE_PARAMS.some((p) => param.includes(p))) score += 30;

  // High-value endpoint patterns
  const JUICY_PATHS = [
    "/api/",
    "/admin",
    "/user",
    "/account",
    "/profile",
    "/search",
    "/upload",
    "/download",
    "/file",
    "/export",
    "/import",
    "/redirect",
    "/oauth",
    "/auth",
  ];
  if (JUICY_PATHS.some((p) => url.includes(p))) score += 20;

  // Vulnerability class weighting
  const HIGH_YIELD_CLASSES = ["sqli", "ssrf", "ssti", "cmdi", "idor", "path-traversal", "xxe"];
  if (HIGH_YIELD_CLASSES.includes(vulnClassHint)) score += 15;

  const shouldExploit = score >= 55;
  const verdict = score >= 65 ? "true_positive" : score >= 45 ? "inconclusive" : "false_positive";

  return {
    verdict,
    confidence: Math.min(score, 90),
    reasoning: `Deterministic score ${score}/100 based on param name "${paramName}", endpoint pattern, and vuln class "${vulnClassHint}"`,
    shouldExploit,
  };
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });
  const db = createClient(SUPABASE_URL, SERVICE_KEY);
  try {
    const body = await req.json();
    const { targetId, runId, endpointUrl, paramName, paramValue, vulnClassHint } = body;
    if (!targetId || !endpointUrl || !paramName) throw new Error("targetId, endpointUrl, paramName required");

    if (await areCreditsRecentlyExhausted(db, targetId, 10)) {
      return new Response(JSON.stringify({ aborted: "ai_credits_exhausted" }), {
        status: 200,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

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
    let proposedPayload = (b1 || "")
      .split("\n")[0]
      .trim()
      .replace(/^[`"']|[`"']$/g, "");

    // 🚫 Refuse to fire LLM-error sentinel strings (e.g. "[B] LLM error 402") as payloads.
    if (isInvalidPayload(proposedPayload)) {
      await db.from("scan_logs").insert({
        target_id: targetId,
        log_type: "info",
        message: `🪫 Debate aborted — Agent B returned no valid payload (LLM unavailable or empty).`,
        metadata: { run_id: runId, phase: "debate-no-payload", raw: b1?.slice(0, 80) },
      });
      return new Response(JSON.stringify({ aborted: "no_payload", fpVerdict: "inconclusive", confidence: 0 }), {
        status: 200,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

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

    // WAF/CDN block detection — baseline 200/302/301 vs mutated 403/406/501 with tiny body = WAF, not FP
    const wafBlocked =
      [200, 301, 302, 303, 307, 308].includes(probe1.baselineStatus) &&
      [403, 406, 419, 429, 451, 501, 503].includes(probe1.status) &&
      probe1.bodyLen < 2000;

    if (probe1.blocked) {
      fpVerdict = "inconclusive";
      confidence = 0;
    } else if (probe1.status === 0 && probe1.baselineStatus === 0) {
      // Both requests failed — cannot judge. Do NOT poison the vault.
      await db.from("scan_logs").insert({
        target_id: targetId,
        log_type: "info",
        message: `🌐 Debate skipped: network unreachable (baseline=${probe1.baselineStatus}, mutated=${probe1.status}) — no insert`,
        metadata: { run_id: runId, phase: "debate-network-skip", endpointUrl, paramName },
      });
      return new Response(JSON.stringify({ skipped: "network_failure", fpVerdict: "inconclusive", confidence: 0 }), {
        status: 200,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    } else if (probe1.status === 0 || probe1.baselineStatus === 0) {
      fpVerdict = "inconclusive";
      confidence = 0;
    } else if (wafBlocked) {
      fpVerdict = "inconclusive";
      confidence = 40;
      probe1.diffReason = `WAF/CDN blocked payload (baseline ${probe1.baselineStatus} → mutated ${probe1.status}, ${probe1.bodyLen}b)`;
    } else if (!probe1.meaningfulDiff) {
      fpVerdict = "false_positive";
      confidence = 90;
    } else if (probe1.diffReason === "sensitive data pattern matched") {
      fpVerdict = "true_positive";
      confidence = 95;
    } else if (probe1.status >= 500 && sqlErrorHit) {
      fpVerdict = "true_positive";
      confidence = 90;
    } else if (probe1.status >= 500 && probe1.baselineStatus < 500) {
      // Server 500 on payload alone is info-disclosure / possible SQLi
      fpVerdict = "true_positive";
      confidence = 78;
      probe1.diffReason = `${probe1.diffReason} | server 500 triggered by payload (info disclosure / possible SQLi)`;
    } else if (probe1.diffReason === "stack trace exposed") {
      fpVerdict = "true_positive";
      confidence = 85;
    } else if (probe1.xssUnescaped || probe1.diffReason?.includes("mutation #")) {
      if (bothAgreeFP) {
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
        if (probe2.status === 0 || probe2.baselineStatus === 0) {
          // Network failure on retest — keep verdict inconclusive
          v2 = "inconclusive";
          c2 = 0;
        } else if (probe2.diffReason === "sensitive data pattern matched") {
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

    // ── Rounds 8-11 — MUTATION LOOP: if still FP, agents propose a
    // fundamentally DIFFERENT attack class (not just a tweaked payload).
    // Up to MAX_MUTATIONS new attack vectors are tried before giving up.
    const MAX_MUTATIONS = 5;
    const mutationProbes: Array<{ vector: string; payload: string; probe: typeof probe1 }> = [];
    let winningProbe = probe1;
    let winningPayload = proposedPayload;
    let winningClass = vulnClassHint || "auto";
    const triedClasses = new Set<string>([(vulnClassHint || "auto").toLowerCase()]);
    let mutationRound = 0;
    while (fpVerdict === "false_positive" && mutationRound < MAX_MUTATIONS && confidence < 95) {
      mutationRound++;
      const sysMutator = `You are a black-hat strategist running attack mutation #${mutationRound}. The previous attempts FAILED to find a bug. You must propose a COMPLETELY DIFFERENT attack class — do not repeat what was already tried.

Already tried vuln classes: ${[...triedClasses].join(", ") || "none"}.
Previously tried payloads: ${[proposedPayload, refinedPayload, ...mutationProbes.map((m) => m.payload)]
        .filter(Boolean)
        .map((p) => p?.slice(0, 60))
        .join(" | ")}.

Available attack classes to switch to: SQLi (UNION/error/boolean/time-based), NoSQLi ($ne/$where), XSS (reflected/DOM/polyglot), SSTI (jinja/twig/freemarker/handlebars), SSRF (file://,gopher://,internal IP,DNS rebind), Path Traversal (../, %2e%2e/, unicode), LFI (php://filter, /proc/self/environ), Command Injection ($(...), backticks, |, ;), HTTP Header Injection (CRLF \\r\\n), Open Redirect, XXE, Prototype Pollution, GraphQL introspection, Race Condition.

Output STRICT format:
LINE 1: vuln_class_name (lowercase, single token)
LINE 2: raw payload only
LINE 3: 1-line rationale

SAFETY: READ-ONLY only. NEVER use DROP/DELETE/UPDATE/INSERT/TRUNCATE/SHUTDOWN/EXEC/rm -rf/format.`;
      const mutUserMsg = `Param: ${paramName}=${paramValue}
URL: ${endpointUrl}
Original hypothesis (FAILED): ${a1.slice(0, 200)}
First payload (FAILED): "${proposedPayload}" → ${probe1.diffReason}
${refinedPayload ? `Skeptic refined (FAILED): "${refinedPayload}" → ${probe2?.diffReason || "n/a"}` : ""}
${mutationProbes.map((m, i) => `Mutation ${i + 1} (${m.vector}, FAILED): "${m.payload}" → ${m.probe.diffReason}`).join("\n")}

Propose a CLEAN-SLATE attack with a DIFFERENT vuln class.`;
      const mutMsg = await callAgent("B", sysMutator, mutUserMsg, []);
      const lines = mutMsg
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter(Boolean);
      const newClass = (lines[0] || "auto").toLowerCase().replace(/[^a-z]/g, "");
      const newPayload = (lines[1] || "").replace(/^[`"']|[`"']$/g, "");
      const rationale = lines.slice(2).join(" ").slice(0, 200);
      transcript.push({
        agent: "B",
        round: 8 + mutationRound,
        msg: `[mutation #${mutationRound} → class=${newClass}] ${mutMsg.slice(0, 300)}`,
      });

      if (!newPayload || triedClasses.has(newClass) || !isSafePayload(newPayload).ok) {
        await db.from("scan_logs").insert({
          target_id: targetId,
          log_type: "info",
          message: `🧬 Mutation #${mutationRound} rejected (class=${newClass}, dup=${triedClasses.has(newClass)}, unsafe=${!isSafePayload(newPayload).ok})`,
          metadata: { run_id: runId, phase: "debate-mutation-reject" },
        });
        continue;
      }
      triedClasses.add(newClass);

      const mProbe = await probe(endpointUrl, paramName, newPayload);
      mutationProbes.push({ vector: newClass, payload: newPayload, probe: mProbe });

      // Score this mutation
      const sql_m = SQL_ERROR_RX.test(mProbe.bodySnippet);
      let mv: any = "false_positive";
      let mc = 60;
      if (mProbe.status === 0 || mProbe.baselineStatus === 0) {
        mv = "inconclusive";
        mc = 0;
      } else if (mProbe.diffReason === "sensitive data pattern matched") {
        mv = "true_positive";
        mc = 95;
      } else if (mProbe.status >= 500 && sql_m) {
        mv = "true_positive";
        mc = 92;
      } else if (mProbe.diffReason === "stack trace exposed") {
        mv = "true_positive";
        mc = 88;
      } else if (mProbe.xssUnescaped) {
        mv = "true_positive";
        mc = 85;
      } else if (mProbe.timingDelta > 4500) {
        mv = "true_positive";
        mc = 80;
      } else if (mProbe.meaningfulDiff && mProbe.status >= 500) {
        mv = "true_positive";
        mc = 78;
      } else if (mProbe.meaningfulDiff) {
        mv = "inconclusive";
        mc = 55;
      }

      await db.from("scan_logs").insert({
        target_id: targetId,
        log_type: mv === "true_positive" ? "result" : "action",
        message: `🧬 Mutation #${mutationRound} [${newClass}] → ${newPayload.slice(0, 60)} | ${mProbe.baselineStatus}→${mProbe.status} ${mProbe.baselineLen}→${mProbe.bodyLen}b | ${mv} (${mc}%) — ${rationale.slice(0, 80)}`,
        metadata: { run_id: runId, phase: "debate-mutation", vuln_class: newClass, payload: newPayload },
      });

      // Critical pipeline fix: a later mutation that is deterministically true-positive
      // must override an earlier high-confidence false-positive. The old `mc > confidence`
      // guard dropped real findings whenever the initial FP was scored 90% and the TP
      // mutation was scored 78-88%.
      if (mv === "true_positive") {
        fpVerdict = mv;
        confidence = mc;
        winningProbe = mProbe;
        winningPayload = newPayload;
        winningClass = newClass;
        probe1.diffReason = `mutation #${mutationRound} [${newClass}] confirmed — ${mProbe.diffReason}`;
        proposedPayload = newPayload;
        break;
      }
    }

    // Self-correlation learnings (now include mutation history)
    const learnA = `Param ${paramName}: hypothesis "${a1.slice(0, 80)}…". Verdict: ${fpVerdict} (${confidence}%). diffReason: ${winningProbe.diffReason}${probe2 ? ` | skeptic-retest: ${probe2.diffReason}` : ""}${mutationProbes.length ? ` | mutations: ${mutationProbes.length} tried (${[...triedClasses].join(",")})` : ""}`;
    const learnB = `Payload "${winningPayload.slice(0, 60)}" → ${fpVerdict}. ${winningProbe.meaningfulDiff ? "Meaningful diff — promote pattern." : "No diff — deprioritize this template."}${refinedPayload ? ` | Skeptic refined: "${refinedPayload.slice(0, 40)}"` : ""}${mutationProbes.length ? ` | Mutation classes attempted: ${[...triedClasses].join(",")}` : ""}`;

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
        agreed_payload: winningPayload,
        agreed_rationale: b1,
        test_result: winningProbe,
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
      const title = `Debate-confirmed: ${winningClass} via ${paramName}`;

      const { data: finding } = await db
        .from("vulnerability_findings")
        .insert({
          target_id: targetId,
          title,
          severity: confidence >= 80 ? "high" : confidence >= 75 ? "medium" : "low",
          description: `Two-agent debate verdict: ${fpVerdict} (${confidence}% conf)\n\n**Diff reason**: ${winningProbe.diffReason}\n**XSS unescaped**: ${winningProbe.xssUnescaped}\n\n**Agent A**: ${a2}\n\n**Agent B**: ${b2}`,
          payload: winningPayload,
          poc: `${endpointUrl}?${paramName}=${encodeURIComponent(winningPayload)}`,
          // Note: vulnerability_findings has no `affected_url` column — URL lives in `poc`.
          confidence_score: confidence,
          confidence_level: confidence >= 75 ? "high" : "medium",
          triage_reasoning: `Agent A: ${a1}\nAgent B: ${b1}\nResult: ${JSON.stringify(winningProbe)}\nDebate: ${a2} | ${b2}`,
          validation_status: validationStatus,
          hard_evidence: {
            baseline_status: winningProbe.baselineStatus,
            baseline_length: winningProbe.baselineLen,
            mutated_status: winningProbe.status,
            mutated_length: winningProbe.bodyLen,
            diff_reason: winningProbe.diffReason,
            xss_unescaped: winningProbe.xssUnescaped,
            timing_delta_ms: winningProbe.timingDelta,
            meaningful_diff: winningProbe.meaningfulDiff,
            body_snippet: winningProbe.bodySnippet,
            skeptic_round: probe2
              ? {
                  refined_payload: refinedPayload,
                  skeptic_msg: skepticMsg,
                  probe: probe2,
                }
              : null,
            mutation_rounds: mutationProbes.length
              ? mutationProbes.map((m) => ({
                  vuln_class: m.vector,
                  payload: m.payload,
                  status: m.probe.status,
                  baseline_status: m.probe.baselineStatus,
                  body_len: m.probe.bodyLen,
                  diff_reason: m.probe.diffReason,
                }))
              : null,
            classes_attempted: [...triedClasses],
            winning_class: winningClass,
          },
        })
        .select("id")
        .single();

      if (confidence >= 75 && finding?.id) {
        const approvalRow = {
          finding_id: finding.id,
          target_id: targetId,
          finding_type: winningClass,
          severity: confidence >= 80 ? "high" : confidence >= 75 ? "medium" : "low",
          title,
          description: `Queued from Mythos debate after mutation-confirmed true positive. ${winningProbe.diffReason}`,
          payload_used: winningPayload,
          evidence: {
            debate_id: debateRow.id,
            winning_class: winningClass,
            mutation_rounds: mutationProbes,
            probe: winningProbe,
          },
          parameter: paramName,
          request_data: { method: "GET", url: endpointUrl, parameter: paramName, payload: winningPayload },
          response_data: {
            status: winningProbe.status,
            length: winningProbe.bodyLen,
            snippet: winningProbe.bodySnippet,
          },
          baseline_response: { status: winningProbe.baselineStatus, length: winningProbe.baselineLen },
          mutated_response: {
            status: winningProbe.status,
            length: winningProbe.bodyLen,
            snippet: winningProbe.bodySnippet,
          },
          confidence_score: confidence,
          confidence_level: "high",
          ai_verified: true,
          ai_verification_notes: `Mythos debate true-positive via ${winningClass}: ${winningProbe.diffReason}`,
          triage_reasoning: `Auto-queued from debate ${debateRow.id}; winning payload overcame earlier false-positive verdict.`,
          reachability_status: "reachable",
          status: "pending",
          cvss_score: confidence >= 88 ? 8.1 : 6.8,
        };
        const { error: approvalErr } = await db.from("pending_approvals").insert(approvalRow as any);
        if (approvalErr) {
          await db.from("scan_logs").insert({
            target_id: targetId,
            log_type: "warning",
            message: `❌ Mythos pending_approvals insert FAILED: ${approvalErr.message}`,
            metadata: { run_id: runId, debate_id: debateRow.id, finding_id: finding.id, approvalRow },
          });
        }

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
            pending_approval_queued: !approvalErr,
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
    if (e instanceof AiCreditsExhaustedError) {
      try {
        const dbErr = createClient(SUPABASE_URL, SERVICE_KEY);
        const body = await req
          .clone()
          .json()
          .catch(() => ({}));
        await markCreditsExhausted(dbErr, { targetId: body?.targetId, runId: body?.runId, phase: "debate" });
      } catch {
        /* ignore */
      }
      return new Response(JSON.stringify({ aborted: "ai_credits_exhausted" }), {
        status: 200,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
    console.error("mythos-debate error:", e);
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : String(e) }), {
      status: 200,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
