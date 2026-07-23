// Deterministic Proof Oracles — per-vuln-class checks that either fire or don't.
// A pass here is stronger than any LLM confidence: it means we saw the exact
// side effect the vuln class demands. Used by findings-writer as an override
// path (oracle pass → promote regardless of AI confidence, oracle fail on a
// class that has an oracle → suppress unless hard marker also present).
//
// Every oracle is pure: (input) → { fired, evidence }. No I/O. Callers gather
// the signals (headless browser events, OOB callbacks, timing pairs, etc.)
// and hand them here for adjudication.

export interface OracleInput {
  vulnClass: string;
  payload: string;
  // Response we're judging
  response?: { status: number; body: string; headers?: Record<string, string> };
  baseline?: { status: number; body: string; headers?: Record<string, string> };
  // Optional signal channels
  browser?: {
    dialogFired?: boolean;
    dialogText?: string;
    consoleErrors?: string[];
    executedNonce?: string;
    domSink?: string;
  };
  oob?: { hit: boolean; token?: string; source?: string };
  timing?: { baselineMs: number; mutatedMs: number };
  differential?: { peerStatus?: number; peerBody?: string };
  nonce?: string; // unique per-payload nonce we injected
}

export interface OracleResult {
  fired: boolean;                // TRUE = exploit is real
  hasOracle: boolean;            // FALSE = no oracle exists for this class (soft-pass)
  reason: string;
  evidence: Record<string, unknown>;
  severity: "info" | "low" | "medium" | "high" | "critical";
}

const CLASSES_WITH_ORACLES = new Set([
  "xss", "reflected_xss", "stored_xss", "dom_xss",
  "sqli", "sqli_boolean_blind", "sqli_time_based", "sqli_error_based",
  "ssrf", "ssrf_basic", "ssrf_oob", "ssrf_cloud_metadata",
  "idor", "bola",
  "rce", "command_injection", "cmdi",
  "open_redirect",
  "auth_bypass", "authbypass", "auth-bypass",
]);

const DB_ERROR_RX = /you have an error in your sql syntax|ORA-\d{4,5}|PG::SyntaxError|PSQLException|SQLServerException|SQLite3::SQLException|Warning: mysql|MariaDB|ODBC SQL Server Driver/i;
const CLOUD_META_RX = /iam\/security-credentials|instance-identity|computeMetadata|ami-id|hostname:\s*ip-\d+-\d+-\d+-\d+/i;
const SHELL_RX = /uid=\d+\(.*?\).*?gid=\d+|root:x:0:0:|\/bin\/(?:ba)?sh/i;

export function runOracle(input: OracleInput): OracleResult {
  const cls = (input.vulnClass || "").toLowerCase().replace(/[_-]+/g, "_");
  const hasOracle = CLASSES_WITH_ORACLES.has(cls) || Array.from(CLASSES_WITH_ORACLES).some((c) => cls.startsWith(c));
  if (!hasOracle) {
    return { fired: false, hasOracle: false, reason: "no oracle for class", evidence: {}, severity: "info" };
  }

  // ─── XSS ───
  if (cls.includes("xss")) {
    const b = input.browser;
    if (b?.dialogFired && input.nonce && (b.dialogText || "").includes(input.nonce)) {
      return { fired: true, hasOracle: true,
        reason: `Browser dialog fired with nonce ${input.nonce}`,
        evidence: { dialogText: b.dialogText, nonce: input.nonce }, severity: "high" };
    }
    if (b?.executedNonce && b.executedNonce === input.nonce) {
      return { fired: true, hasOracle: true,
        reason: "Script executed in DOM with injected nonce",
        evidence: { executedNonce: b.executedNonce, sink: b.domSink }, severity: "high" };
    }
    return { fired: false, hasOracle: true,
      reason: "XSS requires headless-browser execution proof (dialog or nonce). None observed.",
      evidence: { browser: b || null }, severity: "info" };
  }

  // ─── SQLi ───
  if (cls.startsWith("sqli")) {
    const body = input.response?.body || "";
    if (DB_ERROR_RX.test(body)) {
      const match = body.match(DB_ERROR_RX)?.[0] || "";
      return { fired: true, hasOracle: true, reason: `Database error surfaced: ${match.slice(0, 80)}`,
        evidence: { dbError: match, status: input.response?.status }, severity: "high" };
    }
    if (input.timing && input.timing.mutatedMs - input.timing.baselineMs >= 3500) {
      return { fired: true, hasOracle: true,
        reason: `Time-based delta ${input.timing.mutatedMs - input.timing.baselineMs}ms ≥ 3.5s`,
        evidence: { timing: input.timing }, severity: "high" };
    }
    // Boolean-blind requires a pair we don't have here; fail-closed.
    return { fired: false, hasOracle: true,
      reason: "SQLi requires DB error, ≥3.5s timing delta, or boolean pair. None observed.",
      evidence: { timing: input.timing || null }, severity: "info" };
  }

  // ─── SSRF ───
  if (cls.startsWith("ssrf")) {
    if (input.oob?.hit && input.oob.token) {
      return { fired: true, hasOracle: true,
        reason: `OOB callback received for token ${input.oob.token.slice(0, 12)}`,
        evidence: { oob: input.oob }, severity: "critical" };
    }
    const body = input.response?.body || "";
    if (CLOUD_META_RX.test(body)) {
      return { fired: true, hasOracle: true, reason: "Cloud metadata fingerprint returned in body",
        evidence: { snippet: body.match(CLOUD_META_RX)?.[0] }, severity: "critical" };
    }
    return { fired: false, hasOracle: true,
      reason: "SSRF requires OOB hit or cloud-metadata fingerprint. None observed.",
      evidence: {}, severity: "info" };
  }

  // ─── IDOR / BOLA ───
  if (cls === "idor" || cls === "bola") {
    const d = input.differential;
    if (d && d.peerStatus === 200 && input.response?.status === 200) {
      const peerLen = (d.peerBody || "").length;
      const myLen = (input.response.body || "").length;
      const delta = Math.abs(peerLen - myLen) / Math.max(1, Math.max(peerLen, myLen));
      // Same schema, different data: response bodies within 40% of each other
      if (peerLen > 200 && myLen > 200 && delta < 0.4) {
        return { fired: true, hasOracle: true,
          reason: "Cross-account differential: both 200 with same-shape body — record accessible across auth boundary.",
          evidence: { peerLen, myLen, delta }, severity: "high" };
      }
    }
    return { fired: false, hasOracle: true,
      reason: "IDOR requires cross-account 200-vs-200 with matching schema. Not observed.",
      evidence: { differential: d || null }, severity: "info" };
  }

  // ─── RCE / Command Injection ───
  if (cls === "rce" || cls === "command_injection" || cls === "cmdi") {
    if (input.oob?.hit && input.oob.token) {
      return { fired: true, hasOracle: true,
        reason: `Command-injection OOB fired (token ${input.oob.token.slice(0, 12)})`,
        evidence: { oob: input.oob }, severity: "critical" };
    }
    const body = input.response?.body || "";
    if (SHELL_RX.test(body)) {
      return { fired: true, hasOracle: true, reason: "Shell output reflected in response",
        evidence: { snippet: body.match(SHELL_RX)?.[0] }, severity: "critical" };
    }
    return { fired: false, hasOracle: true,
      reason: "RCE requires OOB callback or shell output reflection. None observed.",
      evidence: {}, severity: "info" };
  }

  // ─── Open Redirect ───
  if (cls === "open_redirect") {
    const loc = input.response?.headers?.location || input.response?.headers?.Location || "";
    const status = input.response?.status || 0;
    const isRedirect = status >= 300 && status < 400;
    // Must be an ABSOLUTE URL pointing at an attacker-controlled host from the payload
    if (isRedirect && /^https?:\/\//i.test(loc)) {
      try {
        const target = new URL(loc);
        if (input.payload && (input.payload.includes(target.host) || input.payload.includes(target.hostname))) {
          return { fired: true, hasOracle: true,
            reason: `3xx Location points at attacker host ${target.host}`,
            evidence: { status, location: loc }, severity: "medium" };
        }
      } catch { /* invalid URL, fall through */ }
    }
    return { fired: false, hasOracle: true,
      reason: "Open redirect requires 3xx + Location: absolute URL to payload host.",
      evidence: { status, location: loc }, severity: "info" };
  }

  // ─── Auth Bypass ───
  if (cls === "auth_bypass" || cls === "authbypass") {
    if (input.baseline && input.response) {
      const wasBlocked = input.baseline.status === 401 || input.baseline.status === 403;
      const nowAllowed = input.response.status === 200;
      const gotContent = (input.response.body || "").length > 200;
      if (wasBlocked && nowAllowed && gotContent) {
        return { fired: true, hasOracle: true,
          reason: `Auth bypass: baseline ${input.baseline.status} → mutated 200 with body`,
          evidence: {
            baselineStatus: input.baseline.status,
            mutatedStatus: input.response.status,
            bodyLen: input.response.body.length,
          }, severity: "critical" };
      }
    }
    return { fired: false, hasOracle: true,
      reason: "Auth bypass requires 401/403 → 200 transition with body. Not observed.",
      evidence: {}, severity: "info" };
  }

  return { fired: false, hasOracle: true, reason: "unhandled class", evidence: {}, severity: "info" };
}

/** True if the finding may promote based purely on an oracle firing. */
export function oracleGrantsPromotion(r: OracleResult): boolean {
  return r.fired && r.hasOracle;
}
