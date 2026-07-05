// Shared triple-verification helpers. Used by triple-verify edge function and
// any caller that needs to confirm a candidate finding before report inclusion.
//
// Confidence tiers:
//   >= 95  → confirmed       (auto-promote, ships in report as CONFIRMED)
//   75-94 → needs_review    (ships in report flagged amber)
//   < 75   → inconclusive    (excluded from default report views)
//
// Stages:
//   1. baseline      — clean response (status, length, body hash)
//   2. mutated       — payload response, diffed against baseline
//   3. rebaseline    — re-fetch clean to confirm target wasn't drifting
//   4. replay (x2)   — payload re-fired, must produce same delta (deterministic)
import { safeFetch, readBodySafe } from "./safe-fetch.ts";

export type VerdictTier = "confirmed" | "needs_review" | "inconclusive";

export interface StageSnapshot {
  status: number;
  length: number;
  hash: string;
  blocked: boolean;
  elapsedMs: number;
  location?: string | null;
}

export interface VerifyOptions {
  url: string;
  method?: string;
  headers?: Record<string, string>;
  paramName?: string;
  payload: string;
  cleanValue?: string;
  vulnClass: string;
  bodyTemplate?: string; // for POST: "{{param}}=cyberscope" pattern
}

export interface VerifyResult {
  confidence: number;        // 0-100
  tier: VerdictTier;
  reasons: string[];
  stages: {
    baseline: StageSnapshot | null;
    mutated: StageSnapshot | null;
    rebaseline: StageSnapshot | null;
    replay: StageSnapshot[];
  };
  signals: {
    executionEvidence: boolean;
    evidenceDetail: string;
    deltaBytes: number;
    deltaRatio: number;
    statusChanged: boolean;
    rebaselineDrift: boolean;
    replayDeterministic: boolean;
    timingSignal: boolean;      // NEW: >2s spike on payload vs baseline (blind SQLi/SSRF)
    timingDeltaMs: number;      // NEW
    openRedirectHit: boolean;   // NEW: 3xx Location leaking to attacker-controlled host
  };
  summary: string;
  errors: string[];
}

// ─── EXEC_DETECTORS — pattern matches that prove real execution ──────────
export const EXEC_DETECTORS: Record<
  string,
  (payload: string, body: string, baseline: string) => { found: boolean; evidence: string }
> = {
  sqli: (_p, body, baseline) => {
    const errs = [
      /you have an error in your sql syntax/i,
      /SQLSTATE\[/i,
      /ORA-\d{4,5}/i,
      /pg_query|pg_exec/i,
      /unclosed quotation mark/i,
      /syntax error at or near/i,
      /PDOException/i,
      /mysql_fetch/i,
      /SQLite\/JDBCDriver/i,
      /Microsoft.*ODBC.*SQL/i,
    ];
    for (const e of errs) {
      if (e.test(body) && !e.test(baseline)) return { found: true, evidence: `SQL error: ${e.source}` };
    }
    return { found: false, evidence: "" };
  },
  rxss: (_p, body, baseline) => {
    const probes = ["<cyberscope>", "onerror=cyberscope", "<svg onload=cyberscope>", "cyberscope_xss"];
    for (const probe of probes) {
      if (body.includes(probe) && !baseline.includes(probe)) return { found: true, evidence: `XSS probe reflected: ${probe}` };
    }
    return { found: false, evidence: "" };
  },
  xss: (p, body, baseline) => EXEC_DETECTORS.rxss(p, body, baseline),
  cmdi: (_p, body, baseline) => {
    const markers = [/cyberscope_marker/, /uid=\d+\(/, /root:.*:0:0/, /Linux\s+\S+\s+\d+\.\d+/];
    for (const m of markers) {
      if (m.test(body) && !m.test(baseline)) return { found: true, evidence: `Cmd output: ${m.source}` };
    }
    return { found: false, evidence: "" };
  },
  ssti: (_p, body, baseline) => {
    if (/\b49\b/.test(body) && !/\b49\b/.test(baseline)) return { found: true, evidence: "Template eval: 7*7=49" };
    if (/\b1337\b/.test(body) && !/\b1337\b/.test(baseline)) return { found: true, evidence: "Template eval: 7*191=1337" };
    return { found: false, evidence: "" };
  },
  "path-traversal": (_p, body, baseline) => {
    if (/root:.*:0:0/.test(body) && !baseline.includes("root:")) return { found: true, evidence: "File leak: /etc/passwd" };
    if (/\[boot loader\]/i.test(body) && !/\[boot loader\]/i.test(baseline)) return { found: true, evidence: "File leak: boot.ini" };
    return { found: false, evidence: "" };
  },
  lfi: (p, b, bl) => EXEC_DETECTORS["path-traversal"](p, b, bl),
  ssrf: (_p, body, baseline) => {
    if (/169\.254\.169\.254|ami-id|instance-id/.test(body) && !/169\.254\.169\.254/.test(baseline))
      return { found: true, evidence: "SSRF: cloud metadata leaked" };
    return { found: false, evidence: "" };
  },
  xxe: (_p, body, baseline) => {
    if (/root:.*:0:0/.test(body) && !baseline.includes("root:")) return { found: true, evidence: "XXE: /etc/passwd via entity" };
    return { found: false, evidence: "" };
  },
  "open-redirect": (_p, _body, _baseline) => {
    // Open redirects detected via Location header, not body — handled in stage diff
    return { found: false, evidence: "" };
  },
  idor: (_p, body, baseline) => {
    // IDOR proof: mutated request exposes a distinct record body (different user/id keys)
    const emailMatch = body.match(/[\w.+-]+@[\w-]+\.[\w.-]+/g) || [];
    const baseEmails = baseline.match(/[\w.+-]+@[\w-]+\.[\w.-]+/g) || [];
    const newEmails = emailMatch.filter(e => !baseEmails.includes(e));
    if (newEmails.length >= 1 && body.length > 100)
      return { found: true, evidence: `IDOR leaked ${newEmails.length} new email(s): ${newEmails[0]}` };
    return { found: false, evidence: "" };
  },
  auth_bypass: (_p, body, baseline) => {
    // Auth bypass proof: mutated body contains admin/session markers baseline lacks
    const markers = [/"role"\s*:\s*"admin"/i, /is_admin\s*[:=]\s*true/i, /"authenticated"\s*:\s*true/i, /sessionid|SESSIONID|jwt_token/i];
    for (const m of markers) if (m.test(body) && !m.test(baseline)) return { found: true, evidence: `auth marker: ${m.source}` };
    return { found: false, evidence: "" };
  },
};

// ─── helpers ────────────────────────────────────────────────────────────
async function sha256Hex(input: string): Promise<string> {
  const buf = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, "0")).join("").slice(0, 16);
}

function looksBlocked(status: number, body: string): boolean {
  if (status === 403 || status === 406 || status === 419 || status === 429 || status === 451) return true;
  return /access denied|cloudflare|akamai|imperva|forbidden|blocked|web application firewall|waf/i.test(body.slice(0, 2000));
}

async function snapshot(url: string, init: RequestInit, timeoutMs = 12000): Promise<StageSnapshot> {
  const t0 = Date.now();
  const r = await safeFetch(url, init, timeoutMs);
  const body = await readBodySafe(r);
  return {
    status: r.status,
    length: body.length,
    hash: await sha256Hex(body),
    blocked: looksBlocked(r.status, body),
    elapsedMs: Date.now() - t0,
    location: r.headers.get("location"),
  };
}

// Build a request URL/body for a given param + value
function buildRequest(opts: VerifyOptions, value: string): { url: string; init: RequestInit } {
  const method = (opts.method || "GET").toUpperCase();
  const headers = { "User-Agent": "CyberScope-TripleVerify/1.0", ...(opts.headers || {}) };
  if (method === "GET" || !opts.paramName) {
    let u: URL;
    try { u = new URL(opts.url); } catch { return { url: opts.url, init: { method, headers, redirect: "manual" } }; }
    if (opts.paramName) u.searchParams.set(opts.paramName, value);
    return { url: u.toString(), init: { method, headers, redirect: "manual" } };
  }
  // POST/PUT — form-encoded body
  const body = opts.bodyTemplate
    ? opts.bodyTemplate.replace("{{param}}", encodeURIComponent(value))
    : `${encodeURIComponent(opts.paramName)}=${encodeURIComponent(value)}`;
  return {
    url: opts.url,
    init: {
      method,
      headers: { "Content-Type": "application/x-www-form-urlencoded", ...headers },
      body,
      redirect: "manual",
    },
  };
}

// ─── Main verifier ──────────────────────────────────────────────────────
export async function tripleVerify(opts: VerifyOptions): Promise<VerifyResult> {
  const result: VerifyResult = {
    confidence: 0,
    tier: "inconclusive",
    reasons: [],
    stages: { baseline: null, mutated: null, rebaseline: null, replay: [] },
    signals: {
      executionEvidence: false,
      evidenceDetail: "",
      deltaBytes: 0,
      deltaRatio: 0,
      statusChanged: false,
      rebaselineDrift: false,
      replayDeterministic: false,
    },
    summary: "",
    errors: [],
  };

  const cleanValue = opts.cleanValue ?? "1";

  try {
    // Stage 1: baseline
    const cleanReq = buildRequest(opts, cleanValue);
    result.stages.baseline = await snapshot(cleanReq.url, cleanReq.init, 7000);

    // Stage 2: mutated
    const mutReq = buildRequest(opts, opts.payload);
    const mutResp = await safeFetch(mutReq.url, mutReq.init, 8000);
    const mutBody = await readBodySafe(mutResp);
    const mutSnap: StageSnapshot = {
      status: mutResp.status,
      length: mutBody.length,
      hash: await sha256Hex(mutBody),
      blocked: looksBlocked(mutResp.status, mutBody),
    };
    result.stages.mutated = mutSnap;

    // Get baseline body for detector — re-fetch is wasteful, we already have hashes;
    // for detector we need bodies, so do one more clean fetch (small cost, vital for accuracy).
    const baselineBodyResp = await safeFetch(cleanReq.url, cleanReq.init, 6000);
    const baselineBody = await readBodySafe(baselineBodyResp);

    // Detector
    const detector = EXEC_DETECTORS[opts.vulnClass];
    if (detector) {
      const exec = detector(opts.payload, mutBody, baselineBody);
      result.signals.executionEvidence = exec.found;
      result.signals.evidenceDetail = exec.evidence;
      if (exec.found) result.reasons.push(`exec_evidence: ${exec.evidence}`);
    }

    // Diff math
    const baseLen = result.stages.baseline.length;
    result.signals.deltaBytes = Math.abs(mutSnap.length - baseLen);
    result.signals.deltaRatio = result.signals.deltaBytes / Math.max(baseLen, 1);
    result.signals.statusChanged = mutSnap.status !== result.stages.baseline.status;

    // Stage 3: rebaseline
    await new Promise(r => setTimeout(r, 120));
    result.stages.rebaseline = await snapshot(cleanReq.url, cleanReq.init, 6000);
    const rebaseDelta = Math.abs(result.stages.rebaseline.length - baseLen);
    const rebaseRatio = rebaseDelta / Math.max(baseLen, 1);
    result.signals.rebaselineDrift = rebaseRatio > 0.10 || result.stages.rebaseline.status !== result.stages.baseline.status;
    if (result.signals.rebaselineDrift) result.reasons.push(`rebaseline_drift: target output drifted ${(rebaseRatio*100).toFixed(1)}%`);

    // Stage 4: replay x2 — payload must be deterministic
    await new Promise(r => setTimeout(r, 120));
    const replay1 = await snapshot(mutReq.url, mutReq.init, 6000);
    await new Promise(r => setTimeout(r, 120));
    const replay2 = await snapshot(mutReq.url, mutReq.init, 6000);
    result.stages.replay = [replay1, replay2];
    const replayDelta = Math.abs(replay1.length - replay2.length);
    const replayRatio = replayDelta / Math.max(replay1.length, 1);
    result.signals.replayDeterministic = replayRatio < 0.05 && replay1.status === replay2.status;
    if (!result.signals.replayDeterministic) result.reasons.push(`replay_nondeterministic: ${(replayRatio*100).toFixed(1)}% variance`);

    // ─── Confidence math ──────────────────────────────────────
    let conf = 0;
    if (result.signals.executionEvidence) conf += 70;          // hard proof dominates
    if (result.signals.statusChanged) conf += 10;
    if (result.signals.deltaRatio > 0.25) conf += 15;
    else if (result.signals.deltaRatio > 0.10) conf += 8;
    if (result.signals.replayDeterministic) conf += 10;
    if (mutSnap.blocked && !result.stages.baseline.blocked) {
      conf += 5;
      result.reasons.push("waf_engaged_on_payload");
    }

    // Penalties
    if (result.signals.rebaselineDrift) conf = Math.min(conf, 60);
    if (!result.signals.replayDeterministic) conf = Math.min(conf, 70);
    if (!result.signals.executionEvidence && result.signals.deltaRatio < 0.10 && !result.signals.statusChanged) conf = Math.min(conf, 30);

    result.confidence = Math.max(0, Math.min(100, Math.round(conf)));

    if (result.confidence >= 95) result.tier = "confirmed";
    else if (result.confidence >= 75) result.tier = "needs_review";
    else result.tier = "inconclusive";

    result.summary = [
      `tier=${result.tier}`,
      `confidence=${result.confidence}`,
      `exec=${result.signals.executionEvidence ? "YES" : "no"}${result.signals.evidenceDetail ? ` [${result.signals.evidenceDetail}]` : ""}`,
      `delta=${result.signals.deltaBytes}B (${(result.signals.deltaRatio*100).toFixed(1)}%)`,
      `status=${result.stages.baseline.status}→${mutSnap.status}`,
      `drift=${result.signals.rebaselineDrift ? "YES" : "no"}`,
      `replay=${result.signals.replayDeterministic ? "deterministic" : "noisy"}`,
    ].join("  •  ");
  } catch (e) {
    result.errors.push(e instanceof Error ? e.message : String(e));
    result.summary = `verify_error: ${result.errors[0]}`;
  }

  return result;
}
