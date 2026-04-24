// Shared security/verdict gates used across all scanner edge functions.
// This module enforces the 6 architectural rules in one place so every
// scanner inherits the same behavior:
//   1. Protocol fallback (HTTPS -> HTTP downgrade with strict timeout)
//   2. Zero-payload hallucination kill switch (no payloads -> no severity)
//   3. Gauntlet supremacy (proven=0 -> instant FP, AI cannot resurrect)
//   4. Hard API kill switch (LLM error string -> NEVER fire as payload)
//   5. Strict 500 verdict (500 alone is NOT a vuln; require leak signature)
//   6. Legacy crawler resilience (real browser User-Agent + http downgrade)

export const BROWSER_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

// ─── Rule 4: Hard API Kill Switch ───────────────────────────────
// Detects strings that look like an LLM/API error response which
// should NEVER be sent at a target as if it were a real payload.
const API_ERROR_RX =
  /^(LLM|AI|OpenAI|Gemini|Anthropic|Lovable)[^\n]{0,40}(error|failed)\s*\d{3}|^Error\s*\d{3}\b|"error"\s*:\s*"[^"]{0,200}"|rate[ _-]?limit|payment[ _-]?required|insufficient[ _-]?credits|quota[ _-]?exceeded/i;

const API_ERROR_STATUSES = new Set([402, 429, 500, 502, 503, 504]);

export function isApiErrorPayload(payload: unknown): boolean {
  if (payload == null) return true;
  if (typeof payload !== "string") return true;
  const s = payload.trim();
  if (s.length === 0) return true;
  // anything under 2 chars or that looks like an HTTP error string
  if (API_ERROR_RX.test(s)) return true;
  return false;
}

/**
 * Wrap any AI payload-generation call. On API error (402/429/5xx) or any
 * thrown error, log a [CRITICAL] alert and return null instead of leaking
 * the error string back into the payload pipeline.
 */
export async function safeGeneratePayload(
  fn: () => Promise<string | null | undefined>,
  ctx: { vulnClass?: string; endpoint?: string } = {},
): Promise<string | null> {
  try {
    const out = await fn();
    if (out == null) return null;
    if (typeof out !== "string") {
      console.error(`[CRITICAL] AI payload generator returned non-string for ${ctx.vulnClass || "?"} @ ${ctx.endpoint || "?"}`);
      return null;
    }
    if (isApiErrorPayload(out)) {
      console.error(`[CRITICAL] AI payload looks like an API error string — discarding. (${ctx.vulnClass || "?"})`);
      return null;
    }
    return out;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const m = msg.match(/\b(\d{3})\b/);
    const status = m ? parseInt(m[1], 10) : 0;
    if (API_ERROR_STATUSES.has(status)) {
      console.error(`[CRITICAL] AI payload generation failed with HTTP ${status} — payload thread halted (${ctx.vulnClass || "?"} @ ${ctx.endpoint || "?"})`);
    } else {
      console.error(`[CRITICAL] AI payload generation threw — discarding payload: ${msg}`);
    }
    return null;
  }
}

// ─── Rule 1 + 6: Protocol Fallback Engine ────────────────────────
// Resolve a domain to a working scheme. Try https first with a strict
// 3000ms timeout, downgrade to http on timeout/abort/network error.
export interface ResolvedTarget {
  scheme: "https" | "http";
  baseUrl: string;       // e.g. https://example.com
  hostname: string;
  downgraded: boolean;
  reason?: string;
}

function stripScheme(input: string): string {
  return input.replace(/^https?:\/\//i, "").replace(/\/+$/, "");
}

async function fetchWithTimeout(url: string, ms: number): Promise<Response> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, {
      method: "HEAD",
      headers: { "User-Agent": BROWSER_UA },
      redirect: "manual",
      signal: ctrl.signal,
    });
  } finally {
    clearTimeout(t);
  }
}

export async function resolveTargetProtocol(
  domainOrUrl: string,
  httpsTimeoutMs = 3000,
): Promise<ResolvedTarget> {
  const host = stripScheme(domainOrUrl);
  const httpsUrl = `https://${host}`;
  try {
    const r = await fetchWithTimeout(httpsUrl, httpsTimeoutMs);
    // Even a 4xx/5xx counts as "https reachable"
    if (r.status > 0) {
      return { scheme: "https", baseUrl: httpsUrl, hostname: host, downgraded: false };
    }
  } catch (e) {
    const reason = e instanceof Error ? e.message : "https probe failed";
    // Downgrade
    const httpUrl = `http://${host}`;
    try {
      await fetchWithTimeout(httpUrl, httpsTimeoutMs + 2000);
      return { scheme: "http", baseUrl: httpUrl, hostname: host, downgraded: true, reason };
    } catch {
      // Still return https as the canonical even though both failed —
      // downstream code will surface the network error itself.
      return { scheme: "https", baseUrl: httpsUrl, hostname: host, downgraded: false, reason };
    }
  }
  // Unreachable — but keep TS happy
  return { scheme: "https", baseUrl: httpsUrl, hostname: host, downgraded: false };
}

// ─── Rule 2: Zero-Payload Hallucination Kill Switch ──────────────
// Any finding with payloads_tested === 0 gets confidence forced to 0
// and severity stripped. UI must render these as "info / unverified".
export interface FindingLike {
  payloads_tested?: number;
  payloadsTested?: number;
  confidence_score?: number;
  confidenceScore?: number;
  severity?: string | null;
  validation_status?: string;
  [k: string]: unknown;
}

export function enforceZeroPayloadGate<T extends FindingLike>(f: T): T {
  const tested = Number(f.payloads_tested ?? f.payloadsTested ?? 0) | 0;
  if (tested <= 0) {
    if ("confidence_score" in f) f.confidence_score = 0;
    if ("confidenceScore" in f) f.confidenceScore = 0;
    if (!("confidence_score" in f) && !("confidenceScore" in f)) {
      (f as FindingLike).confidence_score = 0;
    }
    f.severity = "info";
    f.validation_status = "unverified_no_payload";
  }
  return f;
}

// ─── Rule 3: Gauntlet Supremacy ──────────────────────────────────
export interface GauntletOutcome {
  proven: number;        // count of payloads that physically proved the bug
  attempted: number;
  evidence?: unknown;
}

export function gauntletPassed(g: GauntletOutcome | null | undefined): boolean {
  if (!g) return false;
  return Number(g.proven) > 0 && Number(g.attempted) > 0;
}

export function applyGauntletVerdict<T extends FindingLike>(
  f: T,
  g: GauntletOutcome | null | undefined,
): T & { gauntlet_verdict: "passed" | "false_positive" } {
  const passed = gauntletPassed(g);
  (f as FindingLike).gauntlet_verdict = passed ? "passed" : "false_positive";
  if (!passed) {
    (f as FindingLike).confidence_score = 0;
    (f as FindingLike).confidenceScore = 0;
    f.severity = "info";
    f.validation_status = "false_positive_gauntlet";
  }
  return f as T & { gauntlet_verdict: "passed" | "false_positive" };
}

// AI peer review must refuse anything the gauntlet didn't pass.
export function aiReviewAllowed(f: FindingLike): boolean {
  return f.gauntlet_verdict === "passed" && f.validation_status !== "false_positive_gauntlet";
}

// ─── Rule 5: Strict 500 Verdict ──────────────────────────────────
// A 500 status is only a real positive when the response body leaks
// a known database / runtime stack trace.
const LEAK_SIGNATURES = [
  /OleDbException/i,
  /SqlException/i,
  /System\.Data\.SqlClient/i,
  /MySQL[ -]server[ -]version/i,
  /You have an error in your SQL syntax/i,
  /unclosed quotation mark after the character string/i,
  /pg_query|PostgreSQL.*ERROR|PG::SyntaxError/i,
  /ORA-\d{5}/i,
  /SQLSTATE\[\w+\]/i,
  /Microsoft OLE DB Provider/i,
  /Warning:\s*mysql_/i,
  /syntax error.{0,200}\bnear\b/i,
  /Traceback \(most recent call last\)/i,
  /at [\w.$<>]+ \([\w./:]+\.(java|kt|scala):\d+\)/, // JVM stack
  /\bat\s+\w+\s+\([^)]+\.js:\d+:\d+\)/,             // JS stack
  /Stack trace:[\s\S]{0,200}#\d+/i,                  // PHP
];

export interface VerdictInput {
  status: number;
  body: string;
  payloadEcho?: boolean;   // payload reflected verbatim
  diffBytes?: number;      // |true - false| body length
}

export interface Verdict {
  result: "true_positive" | "false_positive" | "inconclusive";
  confidence: number; // 0-100
  reason: string;
  leakMatched?: string;
}

export function verdictFromResponse(input: VerdictInput): Verdict {
  const { status, body, payloadEcho, diffBytes = 0 } = input;

  // Rule 5: 500 alone is never a TP.
  if (status === 500) {
    for (const rx of LEAK_SIGNATURES) {
      const m = body.match(rx);
      if (m) {
        return {
          result: "true_positive",
          confidence: 85,
          reason: "500 with explicit stack trace / DB error leak",
          leakMatched: m[0].slice(0, 120),
        };
      }
    }
    return {
      result: "false_positive",
      confidence: 0,
      reason: "500 with no stack trace / leak — server crash, not exploit",
    };
  }

  // Reflected probe in body is strong execution evidence.
  if (payloadEcho) {
    return { result: "true_positive", confidence: 90, reason: "payload reflected in response" };
  }

  // Significant differential without status change = inconclusive
  if (diffBytes > 500) {
    return { result: "inconclusive", confidence: 40, reason: "large body delta, no execution proof" };
  }
  return { result: "false_positive", confidence: 0, reason: "no execution evidence" };
}

// ─── Rule 6: Default headers for any crawl/probe ────────────────
export function browserHeaders(extra: Record<string, string> = {}): Record<string, string> {
  return {
    "User-Agent": BROWSER_UA,
    "Accept":
      "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
    ...extra,
  };
}
